"""
Module 5: Verifier (验证执行模块)

Automated vulnerability verification with strong safety constraints.

Key safety features:
1. ALL verification through sandboxed HTTP requests (no local execution)
2. Destructive SQL operations blocked (DROP, DELETE, UPDATE, INSERT, etc.)
3. XSS verification uses benign payloads (no cookie theft)
4. Path traversal only reads known-safe files
5. Rate limiting to avoid DoS
6. Full request/response evidence capture

Verification strategies per vulnerability type:
- SQLi: Error-based + Time-based detection
- XSS: Marker reflection + context analysis
- SSRF: Internal address probing
- IDOR: Adjacent ID testing
- Path Traversal: Known-safe file reading
- Command Injection: Time-based detection (safe)

Design principle: "First, do no harm." If verification might be destructive,
the verifier refuses and marks it for human review instead.
"""

import time
from typing import Dict, List, Optional, Any

from utils.logger import get_logger

logger = get_logger("agent.verifier")


class Verifier:
    """
    Safe vulnerability verification engine.

    Usage:
        verifier = Verifier(sandbox, llm_client, config)
        results = verifier.verify_all(confirmed_findings, parsed_task)
    """

    # Vulnerability type → verification method mapping
    VERIFIER_MAP = {
        "sql_injection": "verify_sqli",
        "xss": "verify_xss",
        "ssrf": "verify_ssrf",
        "idor": "verify_idor",
        "path_traversal": "verify_path_traversal",
        "command_injection": "verify_command_injection",
    }

    def __init__(self, sandbox, llm_client, config: Dict[str, Any]):
        """
        Initialize the verifier.

        Args:
            sandbox: Sandbox instance for safe execution
            llm_client: LLMClient for PoC generation
            config: Full agent configuration
        """
        self.sandbox = sandbox
        self.llm = llm_client
        self.config = config
        self.verify_config = config.get("verification", {})
        self.max_verification_time = self.verify_config.get("max_verification_time", 300)
        self.safe_mode = self.verify_config.get("safe_mode", True)

    def verify_all(
        self,
        findings: List[Dict[str, Any]],
        parsed_task: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Verify findings. Skips dangerous verification types that can
        crash fragile targets (path traversal, command injection).
        """
        if not findings:
            logger.info("No findings to verify")
            return []

        # Skip verification for types that can hang/crash the target
        SKIP_VERIFY_TYPES = {"path_traversal", "command_injection"}

        logger.info(f"Starting verification for {len(findings)} findings...")
        verified_findings = []
        target_dead = False

        for finding in findings:
            vuln_type = finding.get("vuln_type", "")

            # Skip dangerous verification types
            if vuln_type in SKIP_VERIFY_TYPES:
                finding["verified"] = False
                finding["verification_note"] = (
                    f"Verification skipped for {vuln_type} — "
                    "can hang or crash fragile test targets. "
                    "Finding based on source code analysis."
                )
                verified_findings.append(finding)
                continue

            # Skip if target is already unresponsive
            if target_dead:
                finding["verified"] = False
                finding["verification_note"] = "Target unresponsive — verification skipped"
                verified_findings.append(finding)
                continue

            verifier_method = self.VERIFIER_MAP.get(vuln_type)
            if not verifier_method:
                finding["verified"] = False
                finding["verification_note"] = f"No verifier for type: {vuln_type}"
                verified_findings.append(finding)
                continue

            try:
                result = self._verify_finding(finding, parsed_task)
                finding["verified"] = result.get("verified", False)
                finding["verification_result"] = result
                finding["verification_evidence"] = result.get("evidence", {})

                if result.get("verified"):
                    logger.info(f"  VERIFIED: {finding.get('title', vuln_type)}")
                elif "timeout" in str(result.get("error", "")).lower() or \
                     "connection" in str(result.get("error", "")).lower():
                    target_dead = True
                    logger.warning(f"  Target appears unresponsive, skipping remaining verifications")
                else:
                    logger.info(f"  Not verified: {finding.get('title', vuln_type)}")

            except Exception as e:
                logger.error(f"  Verification error: {e}")
                finding["verified"] = False
                finding["verification_error"] = str(e)
                if "timeout" in str(e).lower() or "connection" in str(e).lower():
                    target_dead = True

            verified_findings.append(finding)

        verified_count = sum(1 for f in verified_findings if f.get("verified"))
        logger.info(f"Verification complete: {verified_count}/{len(verified_findings)} verified")
        return verified_findings

    def _verify_finding(
        self, finding: Dict, parsed_task: Dict
    ) -> Dict[str, Any]:
        """
        Verify a single finding using the appropriate method.

        Extracts target URL, parameter, method from the finding and
        delegates to the sandbox for safe verification.

        When HTTP method is uncertain, tries multiple method+location combinations
        and returns the best result.
        """
        vuln_type = finding.get("vuln_type", "")
        location = finding.get("location", "")
        evidence = finding.get("evidence", {})

        # Extract verification target from finding
        url = finding.get("endpoint", "") or parsed_task.get("target_url", "")
        param = finding.get("param", "")

        # If no explicit param, try to extract from location
        if not param and "?" in location:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(location)
            params = parse_qs(parsed.query)
            param = list(params.keys())[0] if params else ""

        # If still no param, try from evidence
        if not param:
            param = evidence.get("param", evidence.get("parameter", ""))

        if not url:
            return {"verified": False, "error": "No target URL for verification"}

        if not param:
            return {"verified": False, "error": "No parameter identified for verification"}

        # Try multiple method+location combinations
        # Start with the finding's explicit method if available, then try alternatives
        explicit_method = finding.get("method", "")
        explicit_location = finding.get("param_location", "")
        strategies = []
        if explicit_method and explicit_location:
            strategies.append((explicit_method, explicit_location))
        strategies.extend([
            ("POST", "body"),    # Most common for forms (login, etc.)
            ("GET", "query"),    # Most common for URL params
        ])
        # Deduplicate
        seen = set()
        strategies = [s for s in strategies if not (s in seen or seen.add(s))]

        best_result = None
        for method, param_location in strategies:
            logger.debug(f"  Verifying {vuln_type}: {method} {url} [{param}] @ {param_location}")

            # Dispatch to sandbox method
            if vuln_type in ("sql_injection", "sqli"):
                result = self.sandbox.verify_sqli(url, param, method, param_location)
            elif vuln_type == "xss":
                result = self.sandbox.verify_xss(url, param, method, param_location)
            elif vuln_type == "ssrf":
                result = self.sandbox.verify_ssrf(url, param, method, param_location)
            elif vuln_type == "idor":
                result = self.sandbox.verify_idor(url, param, method)
            elif vuln_type in ("path_traversal", "lfi"):
                result = self.sandbox.verify_path_traversal(url, param, method, param_location)
            elif vuln_type == "command_injection":
                result = self._verify_command_injection(url, param, method, param_location)
            else:
                continue

            # Convert to dict
            if hasattr(result, '__dataclass_fields__'):
                result_dict = {
                    "verified": result.verified,
                    "confidence": result.confidence,
                    "evidence": result.evidence,
                    "error": result.error,
                    "elapsed_seconds": result.elapsed_seconds,
                    "safe": result.safe,
                }
            else:
                result_dict = result

            # Keep best result
            if result_dict.get("verified"):
                result_dict["method_used"] = method
                result_dict["param_location_used"] = param_location
                return result_dict

            if best_result is None:
                best_result = result_dict

        return best_result or {"verified": False, "error": "All verification strategies failed"}

    def _verify_command_injection(
        self, url: str, param: str, method: str = "GET", param_location: str = "query"
    ) -> Dict[str, Any]:
        """
        Verify potential command injection with safe payloads.

        Uses time-based detection with safe commands (sleep/ping).
        NEVER executes destructive commands.
        """
        start = time.time()
        evidence = []

        # Baseline
        baseline = self.sandbox._send_request(url, method, {param: "1"}, param_location)

        # Safe time-based payloads
        safe_payloads = [
            ("; sleep 3 #", "unix_sleep"),
            ("| sleep 3", "unix_sleep_pipe"),
            ("` sleep 3 `", "unix_sleep_backtick"),
            ("& ping -c 3 127.0.0.1 &", "unix_ping"),
        ]

        for payload, payload_type in safe_payloads:
            t_start = time.time()
            resp = self.sandbox._send_request(url, method, {param: payload}, param_location)
            elapsed = time.time() - t_start

            if elapsed > 2.5:
                evidence.append({
                    "type": "time_based",
                    "payload": payload,
                    "response_time_ms": round(elapsed * 1000),
                })

        verified = len(evidence) > 0

        return {
            "verified": verified,
            "confidence": 0.7 if verified else 0.1,
            "evidence": {"details": evidence},
            "safe": True,
            "elapsed_seconds": round(time.time() - start, 2),
        }

    # --- Utility ---

    def get_verification_stats(self) -> Dict[str, Any]:
        """Get verification statistics from sandbox history."""
        return self.sandbox.get_stats()
