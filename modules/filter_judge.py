"""
Module 4: Filter & Judge (过滤研判模块)

Triage engine for vulnerability findings:
1. **Deduplication**: Remove duplicate findings by fingerprinting
2. **Noise reduction**: Apply false-positive rules to filter known noise patterns
3. **Classification**: Three-way verdict — confirmed / false_positive / uncertain
4. **Secondary review**: Re-examine uncertain findings with additional evidence

This module is the quality gate. It ensures the agent doesn't report
false positives as confirmed vulnerabilities, directly impacting the
false-positive rate metric (target: <15%).
"""

import json
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple

from utils.logger import get_logger

logger = get_logger("agent.filter_judge")


class FilterJudge:
    """
    Vulnerability triage and filtering engine.

    Usage:
        fj = FilterJudge(llm_client, config)
        triaged = fj.triage(candidates)
        # triaged = [
        #     {"verdict": "confirmed", "confidence": 0.85, ...},
        #     {"verdict": "false_positive", "confidence": 0.05, ...},
        #     {"verdict": "uncertain", "confidence": 0.55, ...},
        # ]
    """

    # False-positive indicators in code
    FP_PATTERNS = [
        # Test files
        (lambda f: any(p in str(f.get("file_path", "")).lower()
                       for p in ["test_", "_test.", "spec.", "__test__", "tests/", "/test/"]),
         "Test file"),
        # Hard-coded / constant values
        (lambda f: "hardcoded" in str(f.get("evidence", "")).lower(),
         "Hardcoded value"),
        # Input validation present
        (lambda f: any(kw in str(f.get("evidence", ""))
                       for kw in ["int(", "escape(", "sanitize", "validate", "filter_var"]),
         "Input validation detected"),
        # ORM usage (safe by default)
        (lambda f: any(orm in str(f.get("evidence", ""))
                       for orm in [".filter(", ".objects.", "Model.objects", "WHERE ?", "parameterized"]),
         "ORM/parameterized query detected"),
        # Log-only (not exploitable)
        (lambda f: "logger." in str(f.get("evidence", "")) or "console.log" in str(f.get("evidence", "")),
         "Log-only sink"),
        # Environment variable (not user-controllable)
        (lambda f: "os.environ" in str(f.get("evidence", "")) or "process.env" in str(f.get("evidence", "")),
         "Environment variable source"),
        # Commented-out code
        (lambda f: (lambda rm: rm[0].get("matched_text", "").strip().startswith(("//", "#", "/*"))
                    if rm else False)(f.get("rule_matches", [])),
         "Commented-out code"),
        # Dead code (function never called — heuristically determined)
        (lambda f: "def __" in str(f.get("evidence", "")) and "unreachable" in str(f.get("evidence", "")).lower(),
         "Likely dead code"),
    ]

    def __init__(self, llm_client, config: Dict[str, Any]):
        """
        Initialize the filter/judge module.

        Args:
            llm_client: LLMClient instance for deep triage
            config: Full agent configuration
        """
        self.llm = llm_client
        self.config = config
        self.similarity_threshold = config.get("analysis", {}).get(
            "dedup", {}).get("similarity_threshold", 0.85)

        # Track FP patterns that were triggered (for learning)
        self.fp_pattern_history: Dict[str, int] = {}
        self._llm_calls_this_run = 0

    def triage(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Triage a list of candidate findings.

        Process:
        1. Deduplicate by fingerprint
        2. Apply FP rules for noise reduction
        3. Score confidence
        4. Classify into confirmed/FP/uncertain
        5. Secondary review for uncertain findings

        Args:
            candidates: List of candidate findings from Analyzer

        Returns:
            List of triaged findings with verdict and adjusted confidence
        """
        if not candidates:
            return []

        logger.info(f"Triaging {len(candidates)} candidate findings...")

        # Step 1: Deduplicate (already done in analyzer, but re-check)
        unique = self._deduplicate(candidates)

        # Step 2: Apply false-positive rules
        for finding in unique:
            self._apply_fp_rules(finding)

        # Step 3: Score and classify
        for finding in unique:
            self._score_and_classify(finding)

        # Step 4: LLM-assisted triage for ambiguous cases
        ambiguous = [f for f in unique if f.get("verdict") == "uncertain"]
        if ambiguous and len(ambiguous) <= 10:
            logger.info(f"  LLM-assisted triage for {len(ambiguous)} uncertain findings...")
            self._llm_triage(ambiguous)

        # Step 5: Statistics
        confirmed = sum(1 for f in unique if f.get("verdict") == "confirmed")
        fps = sum(1 for f in unique if f.get("verdict") == "false_positive")
        uncertain = sum(1 for f in unique if f.get("verdict") == "uncertain")

        logger.info(f"Triaged: {confirmed} confirmed, {fps} FP, {uncertain} uncertain "
                   f"(from {len(candidates)} candidates)")

        return unique

    # --- Deduplication ---

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings based on content fingerprint."""
        seen: Set[str] = set()
        unique = []

        for f in findings:
            fingerprint = self._make_fingerprint(f)
            if fingerprint not in seen:
                seen.add(fingerprint)
                f["fingerprint"] = fingerprint
                unique.append(f)
            else:
                logger.debug(f"Duplicate removed: {f.get('title', 'unknown')}")

        return unique

    def _make_fingerprint(self, finding: Dict) -> str:
        """Create a unique fingerprint for a finding."""
        rule_matches = finding.get("rule_matches", [])
        first_rule_id = rule_matches[0].get("rule_id", "") if rule_matches else ""
        key_parts = [
            finding.get("vuln_type", ""),
            finding.get("location", ""),
            finding.get("param", ""),
            str(first_rule_id),
        ]
        key = "|".join(key_parts)
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    # --- False-positive rules ---

    def _apply_fp_rules(self, finding: Dict) -> None:
        """
        Apply false-positive detection rules to a finding.

        Marks findings that match known FP patterns.
        """
        fp_reasons = []

        for pattern_fn, reason in self.FP_PATTERNS:
            try:
                if pattern_fn(finding):
                    fp_reasons.append(reason)
                    # Track for analysis
                    self.fp_pattern_history[reason] = \
                        self.fp_pattern_history.get(reason, 0) + 1
            except Exception:
                continue

        if fp_reasons:
            finding["fp_indicators"] = fp_reasons
            # Downgrade confidence
            penalty = min(0.6, 0.15 * len(fp_reasons))
            finding["confidence"] = max(0.05, finding.get("confidence", 0.5) - penalty)
            finding["fp_penalty"] = penalty
            logger.debug(f"FP indicators for '{finding.get('title', '?')}': {fp_reasons}")

    # --- Scoring and classification ---

    def _score_and_classify(self, finding: Dict) -> None:
        """
        Calculate final confidence score and classify the finding.

        Scoring formula:
            score = rule_confidence × 0.6 + llm_confidence × 0.3 + evidence_bonus

        Classification thresholds:
            score >= 0.70 → confirmed
            score < 0.30  → false_positive
            otherwise     → uncertain
        """
        rule_conf = finding.get("confidence", 0.5)

        # LLM confidence (if available)
        llm_conf = finding.get("llm_confidence", rule_conf)

        # Evidence bonus
        evidence_bonus = 0.0
        has_rule_match = bool(finding.get("rule_matches"))
        has_llm_analysis = bool(finding.get("llm_analysis"))
        has_code_loc = bool(finding.get("location"))
        is_llm_only = finding.get("llm_only", False)

        if has_rule_match:
            evidence_bonus += 0.1
        if has_llm_analysis:
            evidence_bonus += 0.05
        if has_code_loc:
            evidence_bonus += 0.05

        # Calculate weighted score
        if is_llm_only:
            # LLM-only findings get lower base confidence
            score = llm_conf * 0.4 + evidence_bonus
        else:
            score = rule_conf * 0.6 + llm_conf * 0.3 + evidence_bonus

        # Apply FP penalties
        fp_penalty = finding.get("fp_penalty", 0.0)
        score = max(0.0, min(1.0, score - fp_penalty))

        # Reflection downgrade
        if finding.get("reflection_note"):
            score *= 0.85

        # Classification
        finding["confidence"] = round(score, 3)

        if score >= 0.70:
            finding["verdict"] = "confirmed"
        elif score < 0.30:
            finding["verdict"] = "false_positive"
        else:
            finding["verdict"] = "uncertain"

        finding["score_breakdown"] = {
            "rule_confidence": round(rule_conf, 3),
            "llm_confidence": round(llm_conf, 3),
            "evidence_bonus": round(evidence_bonus, 3),
            "fp_penalty": round(fp_penalty, 3),
            "final_score": round(score, 3),
        }

    # --- LLM-assisted triage ---

    def _llm_triage(self, uncertain_findings: List[Dict]) -> None:
        """
        Use LLM to help classify uncertain findings.

        The LLM reviews borderline cases with additional context to
        determine if they're likely real or false positives.
        """
        findings_json = json.dumps([{
            "id": i,
            "vuln_type": f.get("vuln_type"),
            "title": f.get("title"),
            "location": f.get("location"),
            "confidence": f.get("confidence"),
            "evidence": str(f.get("evidence", ""))[:300],
            "fp_indicators": f.get("fp_indicators", []),
            "llm_only": f.get("llm_only", False),
        } for i, f in enumerate(uncertain_findings)], indent=2, ensure_ascii=False)

        try:
            prompt = self.llm.load_prompt("filter_judge", findings_json=findings_json)
            if not prompt:
                prompt = f"""Review these uncertain security findings and classify each:
{findings_json}
Return JSON array with verdict and confidence for each."""

            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system_prompt="You are a vulnerability triage specialist. Return valid JSON only.",
                temperature=0.1,
            )
            self._llm_calls_this_run += 1

            # Parse response
            import re
            json_match = re.search(r'\[.*\]', response.content, re.DOTALL)
            if json_match:
                verdicts = json.loads(json_match.group(0))
                if isinstance(verdicts, list):
                    for v in verdicts:
                        idx = v.get("finding_id", v.get("id", -1))
                        if isinstance(idx, int) and 0 <= idx < len(uncertain_findings):
                            verdict = v.get("verdict", "uncertain")
                            new_confidence = v.get("confidence", uncertain_findings[idx].get("confidence", 0.5))

                            uncertain_findings[idx]["verdict"] = verdict
                            uncertain_findings[idx]["confidence"] = new_confidence
                            uncertain_findings[idx]["llm_triage_reasoning"] = v.get("reasoning", "")
                            uncertain_findings[idx]["llm_triage_action"] = v.get("suggested_action", "")

        except Exception as e:
            logger.warning(f"LLM triage failed: {e}")

    # --- Utility ---

    def get_fp_pattern_stats(self) -> Dict[str, int]:
        """Get statistics on which FP patterns were triggered most."""
        return dict(self.fp_pattern_history)

    def reset(self) -> None:
        """Reset state for a new run."""
        self.fp_pattern_history = {}
        self._llm_calls_this_run = 0
