"""
Module 3: Analyzer — Analysis & Reasoning Engine (分析推理模块)

This is the CORE module of the agent. It implements a dual-engine architecture:

1. **Rule Engine (FAST PATH)**: Deterministic pattern matching
   - Scans source code for dangerous function calls (sinks) and user input (sources)
   - Scans HTTP responses for SQL errors, XSS reflection, information disclosure
   - Scans endpoint parameters for vulnerability-prone names
   - ~80% of findings come through this path — zero hallucination risk

2. **LLM Engine (DEEP PATH)**: AI-powered deep analysis
   - Only activated for code/files/endpoints that passed the rule engine filter
   - Provides context-aware reasoning about data flow, exploitability
   - Self-reflection: initial analysis → re-examine → final conclusion
   - Controlled via token budget and context limits

The dual-engine design minimizes LLM costs while maintaining high detection rates.
Rule engine provides precision; LLM provides depth for complex cases.
"""

import json
import re
from typing import Dict, List, Optional, Any, Tuple

from utils.logger import get_logger

logger = get_logger("agent.analyzer")


class Analyzer:
    """
    Dual-engine vulnerability analysis.

    Usage:
        analyzer = Analyzer(rule_engine, llm_client, config)
        findings = analyzer.analyze(parsed_task, inventory)
        # findings = [
        #     {
        #         "vuln_type": "sql_injection",
        #         "severity": "high",
        #         "confidence": 0.85,
        #         "title": "SQL injection in login form",
        #         "location": "app.py:42",
        #         "rule_matches": [...],
        #         "llm_analysis": "...",
        #         "evidence": {...},
        #     }
        # ]
    """

    def __init__(self, rule_engine, llm_client, config: Dict[str, Any]):
        """
        Initialize the analyzer.

        Args:
            rule_engine: RuleEngine instance
            llm_client: LLMClient instance
            config: Full agent configuration
        """
        self.rule_engine = rule_engine
        self.llm = llm_client
        self.config = config
        self.analysis_config = config.get("analysis", {})

        self.rule_enabled = self.analysis_config.get("rule_engine", {}).get("enabled", True)
        self.llm_enabled = self.analysis_config.get("llm_analysis", {}).get("enabled", True)
        self.reflective_rounds = self.analysis_config.get("llm_analysis", {}).get("reflective_rounds", 2)
        self.max_code_snippet_lines = self.analysis_config.get("llm_analysis", {}).get("max_code_snippet_lines", 100)

        # Track LLM usage per run
        self._llm_calls_this_run = 0

    def analyze(
        self, parsed_task: Dict[str, Any], inventory: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Run the full analysis pipeline.

        Args:
            parsed_task: Structured task from TaskParser
            inventory: Asset inventory from InfoCollector

        Returns:
            List of candidate vulnerability findings
        """
        self._llm_calls_this_run = 0
        vuln_types = parsed_task.get("vuln_types", [])
        target_url = parsed_task.get("target_url", "")

        logger.info(f"Starting analysis: {len(inventory.get('files', []))} files, "
                    f"{len(inventory.get('endpoints', []))} endpoints")

        all_findings: List[Dict] = []

        # ── FAST PATH: Rule Engine ──
        if self.rule_enabled:
            logger.info("  [Rule Engine] Scanning...")

            # Analyze source code files
            rule_findings_code = self._analyze_code_with_rules(inventory.get("files", []))
            # Enrich code findings with endpoint URLs from route decorators
            rule_findings_code = self._enrich_code_findings(
                rule_findings_code, inventory, parsed_task.get("target_url", "")
            )
            all_findings.extend(rule_findings_code)
            logger.info(f"  [Rule Engine] Code scan: {len(rule_findings_code)} findings")

            # Analyze HTTP endpoints and responses
            rule_findings_http = self._analyze_endpoints_with_rules(
                inventory.get("endpoints", []),
                inventory.get("raw_responses", {}),
            )
            all_findings.extend(rule_findings_http)
            logger.info(f"  [Rule Engine] HTTP scan: {len(rule_findings_http)} findings")

            # Analyze parameters
            rule_findings_params = self._analyze_params_with_rules(
                inventory.get("endpoints", []),
            )
            all_findings.extend(rule_findings_params)
            logger.info(f"  [Rule Engine] Param scan: {len(rule_findings_params)} findings")

        rule_total = len(all_findings)
        logger.info(f"  [Rule Engine] Total: {rule_total} findings")

        # ── DEEP PATH: LLM Analysis ──
        if self.llm_enabled and all_findings:
            logger.info("  [LLM Engine] Deep analysis on rule hits...")

            # Only send files/snippets with rule hits to LLM for context analysis
            llm_findings = self._analyze_with_llm(
                all_findings, parsed_task, inventory
            )
            logger.info(f"  [LLM Engine] {len(llm_findings)} additional insights")

            # Merge: LLM may add context, adjust confidence, or find new issues
            all_findings = self._merge_findings(all_findings, llm_findings)

        # ── Self-Reflection ──
        if self.llm_enabled and self.reflective_rounds > 0:
            high_conf = [f for f in all_findings if f.get("confidence", 0) > 0.7]
            if high_conf:
                logger.info(f"  [Reflection] Re-examining {len(high_conf)} high-confidence findings...")
                all_findings = self._reflect(all_findings, parsed_task)

        # │─ Deduplicate by fingerprint
        all_findings = self._deduplicate(all_findings)

        # Add default severity if missing
        for f in all_findings:
            if "severity" not in f:
                f["severity"] = self._estimate_severity(f.get("vuln_type", "unknown"))

        logger.info(f"Analysis complete: {len(all_findings)} unique candidates")
        return all_findings

    # ═══ Rule Engine Analysis ═══

    def _analyze_code_with_rules(self, files: List[Dict]) -> List[Dict]:
        """Scan source code files with the rule engine."""
        findings = []

        for file_info in files:
            path = file_info.get("path", "unknown")
            language = file_info.get("language", "")
            # Use full content for analysis (not just preview)
            content = file_info.get("content", file_info.get("preview", ""))

            # Scan the content
            matches = self.rule_engine.scan_code(
                code=content,
                file_path=path,
                language=language,
            )

            for match in matches:
                findings.append({
                    "vuln_type": match.vuln_type,
                    "severity": match.severity.value,
                    "confidence": match.confidence,
                    "title": match.rule_name,
                    "description": f"Rule match: {match.rule_id} in {path}",
                    "location": f"{path}:{match.line_number}" if match.line_number else path,
                    "rule_matches": [{
                        "rule_id": match.rule_id,
                        "matched_text": match.matched_text,
                        "line_number": match.line_number,
                        "sink": match.sink,
                        "source": match.source,
                    }],
                    "evidence": match.evidence,
                    "source": "rule_engine",
                    "file_path": path,
                    "line_number": match.line_number,
                })

        return findings

    def _analyze_endpoints_with_rules(
        self,
        endpoints: List[Dict],
        raw_responses: Dict[str, Any],
    ) -> List[Dict]:
        """Scan HTTP responses for vulnerability indicators.

        Scans ALL raw responses (including probe responses with test payloads),
        not just the original endpoint URLs.
        """
        findings = []

        # Scan all raw response entries (includes probe results with payloads)
        for url, response_data in raw_responses.items():
            if not response_data:
                continue

            response_body = response_data.get("body", "")
            response_headers = response_data.get("headers", {})
            response_time = response_data.get("elapsed_seconds", 0) * 1000

            # Extract the payload from the URL for context
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            test_payload = ""
            for values in query_params.values():
                for v in values:
                    if any(c in v for c in ("'", '"', '<', '>', 'sleep', 'alert', '../')):
                        test_payload = v
                        break

            matches = self.rule_engine.scan_response(
                url=url,
                response_body=response_body,
                response_headers=response_headers,
                response_time_ms=response_time,
                request_payload=test_payload,
            )

            for match in matches:
                # Extract probe metadata if this was a probed endpoint
                probe_method = response_data.get("_probe_method", "")
                probe_param = response_data.get("_probe_param", "")
                probe_payload = response_data.get("_probe_payload", "")

                findings.append({
                    "vuln_type": match.vuln_type,
                    "severity": match.severity.value,
                    "confidence": match.confidence,
                    "title": match.rule_name,
                    "description": f"HTTP response analysis: {match.rule_id}",
                    "location": url,
                    "rule_matches": [{
                        "rule_id": match.rule_id,
                        "matched_text": match.matched_text,
                        "evidence": match.evidence,
                    }],
                    "evidence": match.evidence,
                    "source": "rule_engine",
                    "endpoint": url,
                    "method": probe_method or "GET",
                    "param": probe_param or match.matched_text,
                    "param_location": "body" if probe_method == "POST" else "query",
                })

        return findings

    def _analyze_params_with_rules(self, endpoints: List[Dict]) -> List[Dict]:
        """Scan endpoint parameters for vulnerability-prone names."""
        findings = []

        for ep in endpoints:
            url = ep.get("url", "")
            params = ep.get("params", [])

            if not params:
                continue

            matches = self.rule_engine.scan_params(url=url, params=params)

            for match in matches:
                findings.append({
                    "vuln_type": match.vuln_type,
                    "severity": match.severity.value,
                    "confidence": match.confidence,
                    "title": match.rule_name,
                    "description": f"Sensitive parameter '{match.matched_text}' in {url}",
                    "location": f"{url}?{match.matched_text}=...",
                    "rule_matches": [{
                        "rule_id": match.rule_id,
                        "matched_text": match.matched_text,
                        "evidence": match.evidence,
                    }],
                    "evidence": match.evidence,
                    "source": "rule_engine",
                    "endpoint": url,
                    "param": match.matched_text,
                })

        return findings

    # ═══ LLM Analysis ═══

    def _analyze_with_llm(
        self,
        rule_findings: List[Dict],
        parsed_task: Dict,
        inventory: Dict,
    ) -> List[Dict]:
        """
        Use LLM for deep analysis of rule engine hits.

        Strategy:
        1. Bundle findings by file/endpoint
        2. Send rule findings + code context to LLM
        3. LLM determines if findings are real, adjusts confidence, adds insights
        4. Self-reflection on initial conclusions
        """
        target_url = parsed_task.get("target_url", "")
        vuln_types = parsed_task.get("vuln_types", [])
        tech_stack = inventory.get("tech_stack", [])

        llm_findings = []

        # Group findings by file for efficient analysis
        files_with_findings = self._group_by_file(rule_findings)

        for file_path, findings in files_with_findings.items():
            # Find the actual code for this file
            file_data = next(
                (f for f in inventory.get("files", [])
                 if f.get("path") == file_path or f.get("absolute_path") == file_path),
                None
            )

            if not file_data:
                continue

            code_snippet = file_data.get("preview", "")[:self.max_code_snippet_lines * 80]

            # Build LLM prompt
            findings_summary = json.dumps([
                {
                    "type": f.get("vuln_type"),
                    "location": f.get("location"),
                    "rule_match": f.get("rule_matches", [{}])[0].get("matched_text", ""),
                    "sink": f.get("rule_matches", [{}])[0].get("sink", ""),
                    "source": f.get("rule_matches", [{}])[0].get("source", ""),
                }
                for f in findings
            ], indent=2, ensure_ascii=False)

            try:
                prompt = self.llm.load_prompt(
                    "analyzer",
                    target_url=target_url,
                    tech_stack=", ".join(tech_stack) if tech_stack else "unknown",
                    vuln_types=", ".join(vuln_types) if vuln_types else "all",
                    analysis_data=code_snippet[:4000],  # Limit context
                    rule_findings=findings_summary,
                )

                if not prompt:
                    prompt = f"""Analyze this code for security vulnerabilities:
Target: {target_url}
Tech stack: {tech_stack}
Rule engine found: {findings_summary}
Code:
{code_snippet[:3000]}
Return JSON array of vulnerability findings with vuln_type, severity, confidence, evidence."""

                response = self.llm.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system_prompt="You are a senior application security analyst. Return valid JSON only.",
                    temperature=0.1,
                )
                self._llm_calls_this_run += 1

                # Parse LLM response
                try:
                    content = response.content
                    # Try to extract JSON array
                    json_match = re.search(r'\[.*\]', content, re.DOTALL)
                    if json_match:
                        llm_result = json.loads(json_match.group(0))
                        if isinstance(llm_result, list):
                            for item in llm_result:
                                item["source"] = "llm_analysis"
                                item["file_path"] = file_path
                                item["llm_model"] = response.model
                            llm_findings.extend(llm_result)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse LLM analysis response for {file_path}")

                logger.debug(f"LLM analysis: {response.total_tokens} tokens, "
                           f"${response.cost_usd:.4f}")

            except Exception as e:
                logger.warning(f"LLM analysis failed for {file_path}: {e}")
                continue

        # Also analyze endpoints with sensitive parameters (no code needed)
        endpoint_findings = [f for f in rule_findings if "endpoint" in f and "file_path" not in f]
        if endpoint_findings:
            try:
                ep_summary = json.dumps([{
                    "url": f.get("endpoint"),
                    "param": f.get("param"),
                    "type": f.get("vuln_type"),
                } for f in endpoint_findings[:20]], indent=2)

                response = self.llm.chat(
                    messages=[{
                        "role": "user",
                        "content": f"""Analyze these endpoints for vulnerabilities:
Target: {target_url}
Endpoints with sensitive parameters:
{ep_summary}
For each, assess if it's a likely vulnerability and suggest verification approaches.
Return JSON array of findings.""",
                    }],
                    system_prompt="You are a web security analyst. Return valid JSON only.",
                    temperature=0.1,
                )
                self._llm_calls_this_run += 1

                json_match = re.search(r'\[.*\]', response.content, re.DOTALL)
                if json_match:
                    ep_results = json.loads(json_match.group(0))
                    if isinstance(ep_results, list):
                        for item in ep_results:
                            item["source"] = "llm_analysis"
                            item["llm_model"] = response.model
                        llm_findings.extend(ep_results)

            except Exception as e:
                logger.warning(f"LLM endpoint analysis failed: {e}")

        return llm_findings

    def _reflect(
        self, findings: List[Dict], parsed_task: Dict
    ) -> List[Dict]:
        """
        Self-reflection: re-examine high-confidence findings to reduce false positives.

        The LLM is asked to play devil's advocate: "Why might this NOT be a vulnerability?"
        """
        high_conf = [f for f in findings if f.get("confidence", 0) > 0.7]

        if not high_conf:
            return findings

        findings_json = json.dumps([{
            "id": i,
            "type": f.get("vuln_type"),
            "title": f.get("title"),
            "confidence": f.get("confidence"),
            "evidence": str(f.get("evidence", ""))[:200],
        } for i, f in enumerate(high_conf[:5])], indent=2, ensure_ascii=False)

        try:
            response = self.llm.chat(
                messages=[{
                    "role": "user",
                    "content": f"""You are a code reviewer playing devil's advocate.
For each finding below, identify reasons it might be a FALSE POSITIVE:
{findings_json}
For each finding, return: {{"id": <index>, "might_be_fp": true/false, "reason": "...", "adjusted_confidence": 0.0-1.0}}""",
                }],
                system_prompt="You are a code reviewer. Return valid JSON only.",
                temperature=0.2,
            )
            self._llm_calls_this_run += 1

            # Parse reflection results
            json_match = re.search(r'\[.*\]', response.content, re.DOTALL)
            if json_match:
                reflections = json.loads(json_match.group(0))
                if isinstance(reflections, list):
                    for ref in reflections:
                        idx = ref.get("id", -1)
                        if 0 <= idx < len(high_conf):
                            if ref.get("might_be_fp"):
                                # Reduce confidence
                                old_conf = high_conf[idx].get("confidence", 0)
                                new_conf = ref.get("adjusted_confidence", old_conf * 0.7)
                                high_conf[idx]["confidence"] = new_conf
                                high_conf[idx]["reflection_note"] = ref.get("reason", "")
                                logger.debug(f"Reflection: downgraded '{high_conf[idx].get('title')}' "
                                           f"confidence {old_conf:.0%} → {new_conf:.0%}")

        except Exception as e:
            logger.warning(f"Reflection step failed: {e}")

        return findings

    def _enrich_code_findings(
        self,
        findings: List[Dict],
        inventory: Dict,
        target_url: str,
    ) -> List[Dict]:
        """
        Enrich code-based findings with endpoint URLs and parameters.

        Scans the full source file to find:
        1. Route decorators (@app.route("/path"))
        2. Request parameter extraction near the vulnerable code
        Then matches findings to endpoints for verification.
        """
        import re

        # Build a map: file_path → full source content
        file_contents = {}
        for f in inventory.get("files", []):
            content = f.get("content", f.get("preview", ""))
            if content:
                file_contents[f.get("path", "")] = content

        for finding in findings:
            file_path = finding.get("file_path", "")
            line_number = finding.get("line_number", 0)

            # Get the full file content
            content = file_contents.get(file_path, "")
            if not content:
                continue

            lines = content.split("\n")

            # Find the nearest @app.route BEFORE this line
            route = None
            route_methods = ["GET", "POST"]
            route_pattern = r"@(?:app|flask|blueprint)\.route\(['\"]([^'\"]+)['\"](.*?)\)"

            for i in range(line_number - 1, max(0, line_number - 30), -1):
                match = re.search(route_pattern, lines[i])
                if match:
                    route = match.group(1)
                    # Check for methods=["POST"] etc.
                    methods_match = re.search(r"methods\s*=\s*\[(.*?)\]", match.group(2))
                    if methods_match:
                        methods_str = methods_match.group(1)
                        route_methods = [m.strip().strip("'\"") for m in methods_str.split(",")]
                        # Prefer POST over GET for endpoints that accept both
                        if "POST" in route_methods:
                            route_methods = ["POST"]
                    break

            # Find the function this route decorates, and extract request params
            param = ""
            if route and line_number > 0:
                # Look at lines between route and finding for request.form/args.get
                func_start = line_number
                for i in range(line_number - 1, max(0, line_number - 25), -1):
                    if re.search(r"def\s+\w+", lines[i]):
                        func_start = i
                        break

                # Scan function body for request parameter extraction
                for i in range(func_start, min(len(lines), line_number + 1)):
                    line = lines[i]
                    m = re.search(r"request\.(?:form|args|values)\.get\(['\"](\w+)['\"]", line)
                    if m:
                        param = m.group(1)
                        break
                    m = re.search(r"request\.(?:form|args)\[['\"](\w+)['\"]", line)
                    if m:
                        param = m.group(1)
                        break

            if route:
                finding["endpoint"] = target_url.rstrip("/") + route
                finding["method"] = route_methods[0] if route_methods else "GET"
                finding["param"] = param or self._guess_param_from_code(finding)
                finding["param_location"] = "body" if finding["method"] == "POST" else "query"
                finding["location"] = f"{finding['location']} → {finding['endpoint']}"
            elif not finding.get("endpoint"):
                # No route found — try matching with inventory endpoints by param name
                param = self._guess_param_from_code(finding)
                for ep in inventory.get("endpoints", [])[:50]:
                    if ep and param and param in str(ep.get("params", [])):
                        finding["endpoint"] = ep.get("url", "")
                        finding["param"] = param
                        finding["method"] = ep.get("method", "GET")
                        break

        return findings

    def _guess_param_from_code(self, finding: Dict) -> str:
        """Guess the vulnerable parameter name from code evidence."""
        import re
        evidence_text = str(finding.get("evidence", {}))
        # Look for request.form.get('xxx') or request.args.get('xxx')
        match = re.search(r"request\.(?:form|args)\.get\(['\"](\w+)['\"]", evidence_text)
        if match:
            return match.group(1)
        # Look for request.form['xxx'] or request.args['xxx']
        match = re.search(r"request\.(?:form|args)\[['\"](\w+)['\"]", evidence_text)
        if match:
            return match.group(1)
        return ""

    # ═══ Finding Management ═══

    def _merge_findings(
        self,
        rule_findings: List[Dict],
        llm_findings: List[Dict],
    ) -> List[Dict]:
        """
        Merge rule engine findings with LLM analysis.

        Strategy:
        - LLM findings that confirm rule findings → boost confidence
        - LLM findings that refute rule findings → reduce confidence, mark possible FP
        - LLM-only findings (no rule match) → add with lower initial confidence
        """
        merged = list(rule_findings)

        for llm_f in llm_findings:
            llm_type = llm_f.get("vuln_type", "")
            llm_loc = llm_f.get("location", "")

            # Try to match with existing rule finding
            matched = False
            for rule_f in merged:
                if (rule_f.get("vuln_type") == llm_type and
                    rule_f.get("location") == llm_loc):
                    # LLM confirms → boost confidence
                    if not llm_f.get("is_false_positive"):
                        rule_f["confidence"] = min(
                            1.0,
                            rule_f.get("confidence", 0.5) + 0.2
                        )
                        rule_f["llm_analysis"] = llm_f.get("description", "")
                        rule_f["llm_confidence"] = llm_f.get("confidence", 0.5)
                    else:
                        # LLM says false positive
                        rule_f["confidence"] = max(
                            0.1,
                            rule_f.get("confidence", 0.5) - 0.3
                        )
                        rule_f["llm_refutes"] = True
                        rule_f["fp_reason"] = llm_f.get("fp_reason", "")
                    matched = True
                    break

            if not matched:
                # LLM-only finding: add with moderate confidence cap
                llm_f["confidence"] = min(llm_f.get("confidence", 0.5), 0.6)
                llm_f["llm_only"] = True
                merged.append(llm_f)

        return merged

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicate findings by fingerprint."""
        seen = set()
        unique = []

        for f in findings:
            fingerprint = self.rule_engine.fingerprint(
                f.get("vuln_type", "unknown"),
                f.get("location", ""),
                f.get("param", ""),
            )

            if fingerprint not in seen:
                seen.add(fingerprint)
                f["fingerprint"] = fingerprint
                unique.append(f)

        if len(findings) != len(unique):
            logger.info(f"  Dedup: {len(findings)} → {len(unique)} unique findings")

        return unique

    # ═══ Helpers ═══

    def _group_by_file(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by their source file."""
        groups: Dict[str, List[Dict]] = {}
        for f in findings:
            file_path = f.get("file_path", "") or f.get("location", "").split(":")[0]
            if file_path:
                if file_path not in groups:
                    groups[file_path] = []
                groups[file_path].append(f)
        return groups

    def _estimate_severity(self, vuln_type: str) -> str:
        """Estimate default severity for a vulnerability type."""
        severity_map = {
            "sql_injection": "high",
            "command_injection": "critical",
            "deserialization": "critical",
            "ssti": "critical",
            "xxe": "high",
            "ssrf": "medium",
            "xss": "medium",
            "idor": "medium",
            "path_traversal": "medium",
            "csrf": "medium",
            "open_redirect": "low",
            "information_disclosure": "low",
        }
        return severity_map.get(vuln_type, "medium")
