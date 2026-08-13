"""
Rule Engine — YAML-based security vulnerability pattern matching.

This is the FAST path of the dual-engine analyzer. It loads vulnerability
detection rules from YAML files and matches them against:
- Source code (regex patterns, sink/source detection)
- HTTP responses (error signatures, reflection detection)
- Endpoint parameters (sensitive parameter names)

The rule engine is deterministic, cheap, and produces no hallucinations.
It serves as the primary filter: only rule-hits are candidates for deeper
LLM analysis, reducing LLM calls by ~80%.

Key concepts:
- Sink: A dangerous function call (e.g., cursor.execute, os.system, eval)
- Source: User-controllable input (e.g., request.args, $_GET, req.body)
- A vulnerability exists when unsanitized source data reaches a sink
"""

import re
import yaml
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum

from .logger import get_logger

logger = get_logger("agent.rule_engine")


class Severity(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RuleMatch:
    """A single rule match against a target."""

    rule_id: str
    rule_name: str
    vuln_type: str
    severity: Severity
    confidence: float  # 0.0 - 1.0
    matched_pattern: str
    matched_text: str  # The actual text that matched
    location: str  # File path, URL, or parameter name
    line_number: Optional[int] = None
    sink: Optional[str] = None
    source: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CodeSink:
    """A dangerous function call found in source code."""

    function_name: str
    line_number: int
    line_content: str
    arguments: List[str] = field(default_factory=list)
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)


@dataclass
class CodeSource:
    """A user-controllable input source found in source code."""

    expression: str
    line_number: int
    line_content: str
    source_type: str  # e.g., "query_param", "body_param", "header", "cookie"


class RuleEngine:
    """
    YAML-based security rule engine for fast vulnerability pattern matching.

    Usage:
        engine = RuleEngine(rules_dir="rules/")
        engine.load_all_rules()

        # Scan source code
        matches = engine.scan_code(code, file_path="app.py", language="python")

        # Scan HTTP response
        matches = engine.scan_response(
            url="http://target.com?id=1'",
            response_body="SQL syntax error near '1''",
            response_headers={"Server": "Apache/2.4"},
        )

        # Scan endpoint parameters
        matches = engine.scan_params(
            url="http://target.com/user/123",
            params=["id", "file", "path"],
        )
    """

    # Language detection by file extension
    LANGUAGE_MAP = {
        ".py": "python",
        ".php": "php",
        ".java": "java",
        ".js": "javascript",
        ".ts": "javascript",
        ".go": "go",
        ".rb": "ruby",
        ".cs": "csharp",
        ".cpp": "cpp",
        ".c": "c",
        ".swift": "swift",
        ".kt": "kotlin",
    }

    # Universal dangerous function catalog (language-agnostic names)
    DANGEROUS_FUNCTIONS = {
        # Code execution
        "eval": {"type": "code_execution", "severity": Severity.CRITICAL},
        "exec": {"type": "code_execution", "severity": Severity.CRITICAL},
        "system": {"type": "command_injection", "severity": Severity.CRITICAL},
        "popen": {"type": "command_injection", "severity": Severity.CRITICAL},
        "subprocess.call": {"type": "command_injection", "severity": Severity.CRITICAL},
        "subprocess.run": {"type": "command_injection", "severity": Severity.CRITICAL},
        "os.system": {"type": "command_injection", "severity": Severity.CRITICAL},
        "shell_exec": {"type": "command_injection", "severity": Severity.CRITICAL},
        "passthru": {"type": "command_injection", "severity": Severity.CRITICAL},
        # SQL execution
        "execute": {"type": "sql_injection", "severity": Severity.HIGH},
        "query": {"type": "sql_injection", "severity": Severity.HIGH},
        "raw": {"type": "sql_injection", "severity": Severity.HIGH},
        "mysqli_query": {"type": "sql_injection", "severity": Severity.HIGH},
        "db.execute": {"type": "sql_injection", "severity": Severity.HIGH},
        "cursor.execute": {"type": "sql_injection", "severity": Severity.HIGH},
        # File operations
        "open": {"type": "path_traversal", "severity": Severity.HIGH},
        "read_file": {"type": "path_traversal", "severity": Severity.HIGH},
        "send_file": {"type": "path_traversal", "severity": Severity.HIGH},
        "file_get_contents": {"type": "path_traversal", "severity": Severity.HIGH},
        "fopen": {"type": "path_traversal", "severity": Severity.HIGH},
        # Deserialization
        "pickle.load": {"type": "deserialization", "severity": Severity.CRITICAL},
        "pickle.loads": {"type": "deserialization", "severity": Severity.CRITICAL},
        "yaml.load": {"type": "deserialization", "severity": Severity.CRITICAL},
        "unserialize": {"type": "deserialization", "severity": Severity.CRITICAL},
        "json.loads": {"type": "deserialization", "severity": Severity.LOW},
        # HTTP/Network
        "requests.get": {"type": "ssrf", "severity": Severity.HIGH},
        "urllib.request.urlopen": {"type": "ssrf", "severity": Severity.HIGH},
        "http.Get": {"type": "ssrf", "severity": Severity.HIGH},
        "curl_exec": {"type": "ssrf", "severity": Severity.HIGH},
        "file_get_contents": {"type": "ssrf", "severity": Severity.HIGH},
        "fetch": {"type": "ssrf", "severity": Severity.MEDIUM},
        # Template injection
        "render_template_string": {"type": "ssti", "severity": Severity.CRITICAL},
        "render": {"type": "ssti", "severity": Severity.HIGH},
        # Redirect
        "redirect": {"type": "open_redirect", "severity": Severity.MEDIUM},
    }

    # User input source patterns (language-agnostic)
    SOURCE_PATTERNS = [
        # Python (Flask/Django/FastAPI)
        r"request\.args\.get\(['\"]?(\w+)",
        r"request\.form\.get\(['\"]?(\w+)",
        r"request\.args\[['\"]?(\w+)",
        r"request\.form\[['\"]?(\w+)",
        r"request\.get_json\(\)\[['\"]?(\w+)",
        r"request\.json\[['\"]?(\w+)",
        r"request\.headers\[['\"]?(\w+)",
        r"request\.cookies\[['\"]?(\w+)",
        r"request\.values\.get\(['\"]?(\w+)",
        r"@app\.route\(['\"].*?<(\w+)>",
        r"Query\(\)\.(\w+)",
        r"Body\(\)\.(\w+)",
        r"Path\(\)\.(\w+)",
        # PHP
        r"\$_GET\[['\"]?(\w+)",
        r"\$_POST\[['\"]?(\w+)",
        r"\$_REQUEST\[['\"]?(\w+)",
        r"\$_COOKIE\[['\"]?(\w+)",
        r"\$_SERVER\[['\"]?(\w+)",
        r"filter_input\(INPUT_(GET|POST)['\"]?",
        # JavaScript/Node
        r"req\.query\.(\w+)",
        r"req\.body\.(\w+)",
        r"req\.params\.(\w+)",
        r"location\.search",
        r"window\.location",
        # Java
        r"request\.getParameter\(['\"]?(\w+)",
        r"request\.getHeader\(['\"]?(\w+)",
        r"@RequestParam\(['\"]?(\w+)",
        r"@PathVariable\(['\"]?(\w+)",
        r"@RequestBody",
        # Go
        r"r\.URL\.Query\(\)\.Get\(['\"]?(\w+)",
        r"r\.FormValue\(['\"]?(\w+)",
        r"c\.Param\(['\"]?(\w+)",
        r"c\.Query\(['\"]?(\w+)",
        r"c\.PostForm\(['\"]?(\w+)",
    ]

    def __init__(self, rules_dir: str = "rules"):
        """
        Initialize the rule engine.

        Args:
            rules_dir: Directory containing YAML rule files
        """
        self.rules_dir = Path(rules_dir)
        self.rules: Dict[str, List[Dict]] = {}  # vuln_type → list of rule dicts
        self._loaded = False

    # --- Rule loading ---

    def load_all_rules(self) -> int:
        """
        Load all YAML rule files from the rules directory.

        Returns:
            Total number of rules loaded
        """
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory not found: {self.rules_dir}")
            return 0

        total = 0
        for rule_file in self.rules_dir.glob("*.yaml"):
            try:
                count = self._load_rule_file(rule_file)
                total += count
                logger.debug(f"Loaded {count} rules from {rule_file.name}")
            except Exception as e:
                logger.error(f"Failed to load rule file {rule_file.name}: {e}")

        self._loaded = True
        logger.info(f"Rule engine loaded {total} rules across {len(self.rules)} vulnerability types")
        return total

    def _load_rule_file(self, filepath: Path) -> int:
        """Load rules from a single YAML file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            return 0

        vuln_type = data.get("vuln_type", filepath.stem)
        patterns = data.get("patterns", [])

        if vuln_type not in self.rules:
            self.rules[vuln_type] = []

        for pattern in patterns:
            pattern["_source_file"] = filepath.name
            self.rules[vuln_type].append(pattern)

        return len(patterns)

    def add_rule(self, vuln_type: str, rule: Dict[str, Any]) -> None:
        """Programmatically add a single rule."""
        if vuln_type not in self.rules:
            self.rules[vuln_type] = []
        self.rules[vuln_type].append(rule)

    # --- Code scanning ---

    def scan_code(
        self, code: str, file_path: str = "", language: str = ""
    ) -> List[RuleMatch]:
        """
        Scan source code for vulnerability patterns.

        This is the main entry point for code analysis. It:
        1. Detects the programming language from file extension
        2. Finds all dangerous function calls (sinks)
        3. Finds all user input sources
        4. Cross-references sinks with sources for data-flow analysis
        5. Applies YAML rule patterns

        Args:
            code: Source code text
            file_path: Path to the file (used for language detection)
            language: Explicit language override

        Returns:
            List of RuleMatch objects
        """
        if not language:
            language = self._detect_language(file_path)

        lines = code.split("\n")
        matches = []

        # Step 1: Find sinks (dangerous function calls)
        sinks = self._find_sinks(code, lines)

        # Step 2: Find sources (user input points)
        sources = self._find_sources(code, lines)

        # Step 3: Apply YAML rule patterns
        for vuln_type, rules in self.rules.items():
            for rule in rules:
                # Propagate parent vuln_type to each rule for proper classification
                rule["vuln_type"] = vuln_type
                rule_matches = self._apply_code_rule(code, lines, rule, language, file_path)
                matches.extend(rule_matches)

        # Step 4: Cross-reference sinks with sources for additional findings
        if sinks and sources:
            for sink in sinks:
                for source in sources:
                    # Check if source appears before sink (simple data-flow heuristic)
                    if source.line_number <= sink.line_number:
                        vuln_type = self.DANGEROUS_FUNCTIONS.get(
                            sink.function_name.split(".")[-1], {}
                        ).get("type", "unknown")

                        if vuln_type != "unknown":
                            # Check if source variable appears in sink arguments
                            source_var = self._extract_variable(source.expression)
                            if source_var and any(
                                source_var in arg for arg in sink.arguments
                            ):
                                matches.append(RuleMatch(
                                    rule_id=f"SINK_SOURCE_{vuln_type.upper()}",
                                    rule_name=f"Data flow: {source.source_type} → {sink.function_name}",
                                    vuln_type=vuln_type,
                                    severity=self.DANGEROUS_FUNCTIONS.get(
                                        sink.function_name.split(".")[-1], {}
                                    ).get("severity", Severity.MEDIUM),
                                    confidence=0.6,  # Medium confidence for heuristic match
                                    matched_pattern="data_flow",
                                    matched_text=f"{source.expression} → {sink.function_name}",
                                    location=file_path or "unknown",
                                    line_number=sink.line_number,
                                    sink=sink.function_name,
                                    source=source.expression,
                                    evidence={
                                        "sink_line": sink.line_content.strip(),
                                        "source_line": source.line_content.strip(),
                                        "context": sink.context_before[-3:],
                                    },
                                ))

        # Step 4b: Post-process YAML rule matches — reduce confidence if no source found nearby
        # This prevents high-confidence flagging of safe parameterized queries
        for match in matches:
            if match.source is None and match.confidence > 0.6:
                # Check if any source exists in the same file
                if not sources:
                    # No sources found at all → likely safe code, reduce confidence
                    match.confidence = min(match.confidence, 0.45)
                    match.rule_name += " (no user input source found)"

        # Step 5: Standalone sinks — boost confidence if sources exist in the same file
        for sink in sinks:
            func_key = sink.function_name.split(".")[-1]
            func_info = self.DANGEROUS_FUNCTIONS.get(func_key, {})
            if func_info and not any(
                m.sink == sink.function_name and m.line_number == sink.line_number
                for m in matches
            ):
                # Boost confidence if sources exist in same file (data could flow)
                sink_conf = 0.55 if sources else 0.30
                matches.append(RuleMatch(
                    rule_id=f"SINK_ONLY_{func_info.get('type', 'unknown').upper()}",
                    rule_name=f"Dangerous function: {sink.function_name}" +
                             (" (user input in file)" if sources else ""),
                    vuln_type=func_info.get("type", "unknown"),
                    severity=func_info.get("severity", Severity.MEDIUM),
                    confidence=sink_conf,
                    matched_pattern="dangerous_function",
                    matched_text=sink.line_content.strip(),
                    location=file_path or "unknown",
                    line_number=sink.line_number,
                    sink=sink.function_name,
                    evidence={
                        "sink_line": sink.line_content.strip(),
                        "context": sink.context_before[-3:],
                    },
                ))

        logger.debug(f"Code scan: {file_path} → {len(matches)} matches ({len(sinks)} sinks, {len(sources)} sources)")
        return matches

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        ext = Path(file_path).suffix.lower() if file_path else ""
        return self.LANGUAGE_MAP.get(ext, "unknown")

    def _find_sinks(self, code: str, lines: List[str]) -> List[CodeSink]:
        """Find all dangerous function calls in source code."""
        sinks = []
        for i, line in enumerate(lines, 1):
            for func_name, func_info in self.DANGEROUS_FUNCTIONS.items():
                # Match function call patterns
                if func_name in line:
                    # Verify it's a function call, not just a substring
                    pattern = re.escape(func_name) + r"\s*\("
                    if re.search(pattern, line):
                        # Extract arguments
                        args_match = re.search(
                            re.escape(func_name) + r"\s*\((.*?)\)", line
                        )
                        args = []
                        if args_match:
                            args = [a.strip() for a in args_match.group(1).split(",")]

                        # Get context (surrounding lines)
                        context_before = lines[max(0, i - 4):i - 1]
                        context_after = lines[i:min(len(lines), i + 3)]

                        sinks.append(CodeSink(
                            function_name=func_name,
                            line_number=i,
                            line_content=line,
                            arguments=args,
                            context_before=context_before,
                            context_after=context_after,
                        ))

        return sinks

    def _find_sources(self, code: str, lines: List[str]) -> List[CodeSource]:
        """Find all user input sources in source code."""
        sources = []
        for i, line in enumerate(lines, 1):
            for pattern in self.SOURCE_PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    source_type = self._classify_source(pattern)
                    param_name = match.group(1) if match.lastindex else "unknown"
                    sources.append(CodeSource(
                        expression=match.group(0),
                        line_number=i,
                        line_content=line,
                        source_type=f"{source_type}:{param_name}",
                    ))

        return sources

    def _classify_source(self, pattern: str) -> str:
        """Classify a source pattern into a category."""
        if "GET" in pattern or "query" in pattern.lower() or "Query(" in pattern:
            return "query_param"
        elif "POST" in pattern or "body" in pattern.lower() or "Body(" in pattern:
            return "body_param"
        elif "header" in pattern.lower() or "Header(" in pattern:
            return "header"
        elif "cookie" in pattern.lower() or "Cookie" in pattern:
            return "cookie"
        elif "Path(" in pattern or "Param(" in pattern or "params" in pattern:
            return "path_param"
        elif "SERVER" in pattern:
            return "server_var"
        elif "location" in pattern.lower() or "window" in pattern.lower():
            return "client_side"
        return "other"

    def _extract_variable(self, expression: str) -> Optional[str]:
        """Extract a variable name from a source expression."""
        # Patterns like request.args.get('id') → extract 'id'
        match = re.search(r"""get\(['\"]?(\w+)""", expression)
        if match:
            return match.group(1)
        # Patterns like $_GET['id'] → extract 'id'
        match = re.search(r"""\[['\"](\w+)['\"]""", expression)
        if match:
            return match.group(1)
        # Patterns like req.query.id → extract 'id'
        match = re.search(r"""\.(\w+)$""", expression)
        if match:
            return match.group(1)
        return None

    def _apply_code_rule(
        self,
        code: str,
        lines: List[str],
        rule: Dict,
        language: str,
        file_path: str,
    ) -> List[RuleMatch]:
        """Apply a single YAML rule against source code."""
        matches = []

        # Check language filter
        rule_languages = rule.get("languages", [])
        if rule_languages and language not in rule_languages:
            return matches

        # Support both old nested format (rule.patterns[].regex) and
        # new flat format (rule.regex directly)
        rule_patterns = rule.get("patterns", [])
        if isinstance(rule_patterns, dict):
            rule_patterns = [rule_patterns]

        if not rule_patterns and rule.get("regex"):
            # New flat format: the rule itself is the pattern definition
            rule_patterns = [rule]

        for pattern_def in rule_patterns:
            if isinstance(pattern_def, str):
                pattern_regex = pattern_def
                flags = 0
            else:
                pattern_regex = pattern_def.get("regex", "")
                flag_strs = pattern_def.get("flags", [])
                flags = 0
                for f in flag_strs:
                    flags |= getattr(re, f.upper(), 0)

            if not pattern_regex:
                continue

            try:
                compiled = re.compile(pattern_regex, flags)
            except re.error as e:
                logger.warning(f"Invalid regex in rule {rule.get('id', 'unknown')}: {e}")
                continue

            for i, line in enumerate(lines, 1):
                match = compiled.search(line)
                if match:
                    matches.append(RuleMatch(
                        rule_id=rule.get("id", "UNKNOWN"),
                        rule_name=rule.get("name", "Unnamed rule"),
                        vuln_type=rule.get("vuln_type", rule.get("_source_file", "unknown")),
                        severity=Severity(rule.get("severity", "medium")),
                        confidence=rule.get("confidence_base", 0.7),
                        matched_pattern=pattern_regex,
                        matched_text=match.group(0),
                        location=file_path or "unknown",
                        line_number=i,
                        evidence={
                            "line": line.strip(),
                            "rule_file": rule.get("_source_file", ""),
                        },
                    ))

        return matches

    # --- HTTP response scanning ---

    def scan_response(
        self,
        url: str,
        response_body: str,
        response_headers: Optional[Dict[str, str]] = None,
        response_time_ms: float = 0,
        request_payload: str = "",
    ) -> List[RuleMatch]:
        """
        Scan an HTTP response for vulnerability indicators.

        Detects:
        - SQL error messages in response body
        - Reflected XSS payloads
        - Path traversal error messages
        - SSRF response indicators
        - Command injection output
        - Information disclosure in headers

        Args:
            url: The requested URL
            response_body: HTTP response body text
            response_headers: Response headers dict
            response_time_ms: Response time (for time-based detection)
            request_payload: The payload that was sent

        Returns:
            List of RuleMatch objects
        """
        matches = []
        headers = response_headers or {}

        # SQL error detection
        sql_errors = self._check_sql_errors(response_body)
        for error in sql_errors:
            matches.append(RuleMatch(
                rule_id="SQL_ERROR_001",
                rule_name="SQL error in response",
                vuln_type="sql_injection",
                severity=Severity.HIGH,
                confidence=0.85,
                matched_pattern=error["pattern"],
                matched_text=error["text"],
                location=url,
                evidence={"error_type": error["db_type"], "payload": request_payload},
            ))

        # Time-based SQLi detection
        if response_time_ms > 4000 and ("sleep" in request_payload.lower() or "waitfor" in request_payload.lower()):
            matches.append(RuleMatch(
                rule_id="SQL_TIME_001",
                rule_name="Time-based SQL injection",
                vuln_type="sql_injection",
                severity=Severity.HIGH,
                confidence=0.75,
                matched_pattern="response_time",
                matched_text=f"Response time: {response_time_ms}ms",
                location=url,
                evidence={"response_time_ms": response_time_ms, "payload": request_payload},
            ))

        # XSS reflection detection
        if request_payload and len(request_payload) > 3:
            if request_payload in response_body:
                # Check if reflected in an executable context
                executable = self._is_executable_context(response_body, request_payload)
                if executable:
                    matches.append(RuleMatch(
                        rule_id="XSS_REFLECT_001",
                        rule_name="Reflected XSS payload",
                        vuln_type="xss",
                        severity=Severity.MEDIUM,
                        confidence=0.7 if executable else 0.3,
                        matched_pattern="payload_reflection",
                        matched_text=request_payload[:100],
                        location=url,
                        evidence={
                            "reflected": True,
                            "executable_context": executable,
                            "payload": request_payload,
                        },
                    ))

        # Path traversal error detection
        path_traversal_indicators = [
            (r"(root:.*:0:0:|daemon:.*:1:1:)", "passwd_file_leak"),
            (r"(\\x[0-9a-f]{2}){4,}", "binary_leak"),
            (r"java\.lang\.(NullPointer|ArrayIndexOutOfBounds)", "java_error"),
            (r"Warning:.*(include|require)\(.*failed", "php_include_error"),
            (r"\[Errno 2\] No such file or directory", "python_file_error"),
        ]
        for pattern, indicator in path_traversal_indicators:
            if re.search(pattern, response_body, re.IGNORECASE):
                matches.append(RuleMatch(
                    rule_id=f"TRAVERSAL_{indicator.upper()}",
                    rule_name=f"Path traversal indicator: {indicator}",
                    vuln_type="path_traversal",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    matched_pattern=pattern,
                    matched_text="(see response body)",
                    location=url,
                    evidence={"indicator": indicator},
                ))

        # Information disclosure in headers
        # NOTE: Only report X-Powered-By and version headers (Server alone is too noisy)
        sensitive_headers = [
            "X-Powered-By", "X-AspNet-Version",
            "X-Generator", "X-Drupal-Cache", "X-Drupal-Dynamic-Cache",
        ]
        for header_name in sensitive_headers:
            if header_name in headers:
                matches.append(RuleMatch(
                    rule_id="INFO_DISCLOSURE_HEADER",
                    rule_name=f"Information disclosure: {header_name}",
                    vuln_type="information_disclosure",
                    severity=Severity.LOW,
                    confidence=0.5,
                    matched_pattern=header_name,
                    matched_text=headers[header_name],
                    location=url,
                    evidence={"header": header_name, "value": headers[header_name]},
                ))

        return matches

    def _check_sql_errors(self, body: str) -> List[Dict]:
        """Check response body for SQL error messages."""
        errors = []
        error_patterns = [
            # MySQL
            (r"SQL syntax.*?MySQL", "MySQL"),
            (r"Warning.*?mysql_.*?", "MySQL"),
            (r"MySQLSyntaxErrorException", "MySQL"),
            (r"valid MySQL result", "MySQL"),
            # PostgreSQL
            (r"PostgreSQL.*?ERROR", "PostgreSQL"),
            (r"Warning.*?\Wpg_.*?", "PostgreSQL"),
            # Oracle
            (r"ORA-\d{5}", "Oracle"),
            (r"Oracle.*?Driver", "Oracle"),
            # SQLite
            (r"SQLite.*?error", "SQLite"),
            (r"SQLite/JDBCDriver", "SQLite"),
            (r"near\s+\".*?\":\s+syntax error", "SQLite"),       # SQLite syntax error
            (r"unrecognized token:", "SQLite"),                    # SQLite token error
            (r"no such (table|column):", "SQLite"),                # SQLite missing object
            # MSSQL
            (r"Microsoft OLE DB.*?SQL Server", "MSSQL"),
            (r"\[SQL Server\]", "MSSQL"),
            (r"Conversion failed when converting", "MSSQL"),
            # Generic
            (r"Unclosed quotation mark", "Generic"),
            (r"quoted string not properly terminated", "Generic"),
            (r"You have an error in your SQL syntax", "Generic"),
            (r"SQLSTATE\[\d+\]", "Generic"),
            # SQL query leakage (DEBUG comments, error pages showing queries)
            (r"<!--\s*DEBUG:\s*SELECT\b", "QueryLeak"),            # Debug comment with SQL
            (r"DEBUG:\s*SELECT\b", "QueryLeak"),                    # Plain text debug
            (r"Database error:", "Generic"),                        # Generic DB error header
        ]

        for pattern, db_type in error_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                errors.append({
                    "pattern": pattern,
                    "text": match.group(0),
                    "db_type": db_type,
                })

        return errors

    def _is_executable_context(self, body: str, payload: str) -> bool:
        """
        Check if a reflected payload appears in an executable HTML context.

        Returns True if payload appears:
        - Inside a <script> tag
        - Inside an event handler attribute (onclick, onerror, etc.)
        - As an HTML attribute value without encoding
        - Inside a JavaScript string
        """
        # Find where the payload appears
        idx = body.find(payload)
        if idx == -1:
            return False

        context = body[max(0, idx - 100):idx + len(payload) + 100]

        # Check for executable contexts
        executable_patterns = [
            r"<script[^>]*>.*?" + re.escape(payload),
            r"on\w+=\"[^\"]*" + re.escape(payload),
            r"on\w+='[^']*" + re.escape(payload),
            r"javascript:.*?" + re.escape(payload),
            r"<[^>]+=[\"'][^\"']*" + re.escape(payload),
        ]

        for ep in executable_patterns:
            if re.search(ep, context, re.IGNORECASE):
                return True

        return False

    # --- Parameter scanning ---

    def scan_params(self, url: str, params: List[str]) -> List[RuleMatch]:
        """
        Scan endpoint parameters for vulnerability-prone names.

        Identifies parameters that are commonly associated with:
        - SQL injection (id, user_id, etc.)
        - Path traversal (file, path, template)
        - SSRF (url, redirect, callback)
        - Command injection (cmd, exec, command)
        - IDOR (resource IDs in URL)

        Args:
            url: The endpoint URL
            params: List of parameter names

        Returns:
            List of RuleMatch objects
        """
        matches = []

        sensitive_param_map = {
            "sql_injection": ["id", "uid", "user_id", "pid", "post_id", "product_id",
                             "cat", "category", "type", "sort", "order", "filter",
                             "query", "search", "keyword", "q"],
            "path_traversal": ["file", "path", "folder", "directory", "template",
                              "include", "page", "document", "filename", "src",
                              "dir", "load", "read"],
            "ssrf": ["url", "uri", "link", "redirect", "callback", "return",
                    "next", "target", "dest", "destination", "proxy", "fetch",
                    "webhook", "endpoint", "host"],
            "command_injection": ["cmd", "exec", "command", "shell", "run",
                                 "execute", "ping", "action", "do"],
            "idor": ["id", "uid", "user_id", "pid", "profile_id", "account_id",
                    "order_id", "transaction_id", "invoice_id"],
            "xss": ["q", "search", "query", "keyword", "message", "comment",
                   "name", "title", "description", "content", "text", "body"],
        }

        url_lower = url.lower()
        params_lower = [p.lower() for p in params]

        for vuln_type, sensitive_params in sensitive_param_map.items():
            for param in sensitive_params:
                if param in params_lower:
                    matches.append(RuleMatch(
                        rule_id=f"SENSITIVE_PARAM_{vuln_type.upper()}",
                        rule_name=f"Sensitive parameter for {vuln_type}: {param}",
                        vuln_type=vuln_type,
                        severity=self._param_severity(vuln_type, param, url_lower),
                        confidence=0.4,  # Low confidence — parameter name alone isn't proof
                        matched_pattern="sensitive_param",
                        matched_text=param,
                        location=url,
                        evidence={
                            "parameter": param,
                            "url": url,
                        },
                    ))

        return matches

    def _param_severity(self, vuln_type: str, param: str, url: str) -> Severity:
        """Determine severity based on parameter context."""
        # Higher severity for certain URL patterns
        if vuln_type == "sql_injection" and any(
            p in url for p in ["/user/", "/admin/", "/account/"]
        ):
            return Severity.HIGH
        if vuln_type == "command_injection":
            return Severity.CRITICAL
        if vuln_type == "ssrf" and "admin" in url:
            return Severity.HIGH
        return Severity.MEDIUM

    # --- Utility ---

    def get_rules_summary(self) -> Dict[str, int]:
        """Get a summary of loaded rules by vulnerability type."""
        return {vuln_type: len(rules) for vuln_type, rules in self.rules.items()}

    def fingerprint(self, vuln_type: str, location: str, param: str = "") -> str:
        """
        Generate a deduplication fingerprint for a finding.

        This is used by the FilterJudge module to group similar findings.
        """
        key = f"{vuln_type}:{location}:{param}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
