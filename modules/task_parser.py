"""
Module 1: Task Parser (任务解析模块)

Accepts security task input (natural language or structured JSON) and
automatically decomposes it into:
- Target scope identification
- Vulnerability type recognition
- Constraints extraction
- Subtask decomposition
- Human intervention point identification

Supports both:
1. Range-compatible JSON format (structured)
2. Free-text task descriptions (NLP-driven via LLM)
"""

import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from utils.logger import get_logger

logger = get_logger("agent.task_parser")


@dataclass
class SubTask:
    """A decomposed sub-task."""
    id: int
    description: str
    priority: str  # "high", "medium", "low"
    vuln_type: str
    target_endpoint: str = ""
    estimated_effort: str = "medium"


class TaskParser:
    """
    Parses security testing tasks into structured, actionable plans.

    Two parsing strategies:
    1. **Structured**: Direct field extraction from JSON (fast, deterministic)
    2. **NLP-driven**: LLM-powered parsing of free-text descriptions

    Usage:
        parser = TaskParser(llm_client, config)
        parsed = parser.parse({
            "target": "http://example.com",
            "vuln_types": ["sqli", "xss"]
        })
    """

    # Known vulnerability type aliases
    VULN_TYPE_ALIASES = {
        # SQL Injection
        "sql": "sql_injection", "sqli": "sql_injection",
        "sql injection": "sql_injection", "sql注入": "sql_injection",
        # XSS
        "xss": "xss", "cross site scripting": "xss",
        "跨站脚本": "xss", "reflected xss": "xss",
        # SSRF
        "ssrf": "ssrf", "server side request forgery": "ssrf",
        # IDOR
        "idor": "idor", "insecure direct object reference": "idor",
        "越权": "idor", "unauthorized access": "idor",
        # Path Traversal
        "path traversal": "path_traversal", "directory traversal": "path_traversal",
        "lfi": "path_traversal", "文件包含": "path_traversal",
        "path_traversal": "path_traversal",
        # Command Injection
        "command injection": "command_injection", "os command injection": "command_injection",
        "rce": "command_injection", "命令注入": "command_injection",
        "command_injection": "command_injection",
        # CSRF
        "csrf": "csrf", "cross site request forgery": "csrf",
        # Open Redirect
        "open redirect": "open_redirect", "redirect": "open_redirect",
        # Others
        "information disclosure": "information_disclosure",
        "ssti": "ssti", "template injection": "ssti",
        "xxe": "xxe", "xml external entity": "xxe",
        "deserialization": "deserialization",
    }

    # URL regex pattern
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"\'{}|\\^`\[\]]+',
        re.IGNORECASE,
    )

    def __init__(self, llm_client, config: Dict[str, Any]):
        """
        Initialize the task parser.

        Args:
            llm_client: LLMClient instance for NLP parsing
            config: Full agent configuration
        """
        self.llm = llm_client
        self.config = config
        self.agent_config = config.get("agent", {})

    def parse(self, task_input: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a task input into a structured task plan.

        Args:
            task_input: Raw task specification:
                - Structured: {"target": "...", "vuln_types": [...], ...}
                - Text: {"task_text": "..."}

        Returns:
            Structured task dict with all required fields
        """
        # Determine parsing strategy
        if "task_text" in task_input and len(task_input) <= 2:
            # Primarily text description → LLM parsing
            return self._parse_with_llm(task_input["task_text"], task_input)

        # Structured input → direct extraction
        return self._parse_structured(task_input)

    def _parse_structured(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a structured JSON task input.

        Expected fields:
        - target (required): URL or domain to test
        - vuln_types (optional): List of vulnerability types
        - constraints (optional): Testing constraints
        - scope (optional): Extended scope list
        """
        target = task.get("target", task.get("target_url", ""))
        if not target:
            # Try to extract from other fields
            for key in ["url", "host", "domain", "endpoint"]:
                if key in task:
                    target = task[key]
                    break

        if not target:
            logger.warning("No target specified in task input")

        # Normalize target URL
        if target and "://" not in target:
            target = f"http://{target}"

        # Normalize vulnerability types
        raw_types = task.get("vuln_types", [])
        if isinstance(raw_types, str):
            raw_types = [raw_types]
        vuln_types = self._normalize_vuln_types(raw_types)

        # If no vuln types specified, default to common web vulns
        if not vuln_types:
            vuln_types = ["sql_injection", "xss", "idor", "path_traversal", "ssrf"]

        # Parse constraints
        constraints = task.get("constraints", {})
        if not constraints:
            constraints = {
                "destructive_allowed": False,
                "time_budget_seconds": self.agent_config.get("timeout_per_task", 3600),
                "max_depth": 3,
                "rate_limit": 2.0,
            }

        # Generate sub-tasks
        subtasks = self._generate_subtasks(target, vuln_types)

        # Identify potential human intervention points
        human_intervention_points = self._identify_intervention_points(
            target, vuln_types, constraints, task.get("task_text", "")
        )

        parsed = {
            "task_id": task.get("task_id", ""),
            "target_url": target,
            "scope": task.get("scope", [target]) if target else [],
            "vuln_types": vuln_types,
            "constraints": constraints,
            "subtasks": [vars(st) if hasattr(st, '__dataclass_fields__') else st
                        for st in subtasks],
            "human_intervention_points": human_intervention_points,
            "raw_text": task.get("task_text", ""),
            "needs_human": len(human_intervention_points) > 2,
            "auth_credentials": task.get("auth", task.get("credentials")),
            "source_path": task.get("source_path", ""),  # Pass through for code collection
        }

        logger.info(f"Structured parse: {target} → {len(subtasks)} subtasks, "
                    f"{len(vuln_types)} vuln types")
        return parsed

    def _parse_with_llm(self, task_text: str, task_input: Dict) -> Dict[str, Any]:
        """
        Use LLM to parse a natural language task description.

        Args:
            task_text: Free-text task description
            task_input: Original input dict for merging

        Returns:
            Structured task dict
        """
        logger.info("Using LLM for task parsing...")

        # Try to extract URL directly first (fast path)
        url_match = self.URL_PATTERN.search(task_text)
        extracted_url = url_match.group(0) if url_match else ""

        # Try to extract vuln types from text
        text_lower = task_text.lower()
        hinted_types = []
        for alias, normalized in self.VULN_TYPE_ALIASES.items():
            if alias in text_lower and normalized not in hinted_types:
                hinted_types.append(normalized)

        # Use LLM for deep parsing
        try:
            prompt = self.llm.load_prompt("task_parser", task_text=task_text)
            if not prompt:
                # Fallback: construct prompt inline
                prompt = f"""Analyze this security testing task and extract structured information:
Task: {task_text}
Return JSON with: target_url, scope, vuln_types, constraints, subtasks, human_intervention_points, needs_human"""

            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system_prompt="You are a security task analyzer. Return only JSON.",
                temperature=0.0,
            )

            # Try to extract JSON from response
            content = response.content
            # Find JSON object in response
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                llm_result = json.loads(json_match.group(0))
            else:
                llm_result = {}

            # Log cost
            logger.debug(f"Task parsing LLM: {response.total_tokens} tokens, "
                        f"${response.cost_usd:.4f}")

        except Exception as e:
            logger.warning(f"LLM task parsing failed: {e}, using rules-based extraction")
            llm_result = {}

        # Merge LLM results with direct extraction
        target = llm_result.get("target_url", "") or extracted_url
        vuln_types = self._normalize_vuln_types(
            llm_result.get("vuln_types", hinted_types)
        )
        constraints = llm_result.get("constraints", {})
        llm_subtasks = llm_result.get("subtasks", [])

        if target and "://" not in target:
            target = f"http://{target}"

        subtasks = self._generate_subtasks(target, vuln_types)
        if not subtasks and llm_subtasks:
            subtasks = [SubTask(
                id=s.get("id", i + 1),
                description=s.get("description", ""),
                priority=s.get("priority", "medium"),
                vuln_type=s.get("vuln_type", "unknown"),
            ) for i, s in enumerate(llm_subtasks)]

        human_points = llm_result.get("human_intervention_points", [])
        if not human_points:
            human_points = self._identify_intervention_points(
                target, vuln_types, constraints, task_text
            )

        parsed = {
            "task_id": task_input.get("task_id", ""),
            "target_url": target,
            "scope": llm_result.get("scope", [target]) if target else [],
            "vuln_types": vuln_types,
            "constraints": constraints,
            "subtasks": [vars(st) if hasattr(st, '__dataclass_fields__') else st
                        for st in subtasks],
            "human_intervention_points": human_points,
            "raw_text": task_text,
            "needs_human": llm_result.get("needs_human", False),
            "source_path": task_input.get("source_path", ""),
        }

        return parsed

    # --- Helper methods ---

    def _normalize_vuln_types(self, raw_types: List[str]) -> List[str]:
        """Normalize vulnerability type strings to canonical names."""
        normalized = []
        for vt in raw_types:
            vt_lower = vt.lower().strip()
            canonical = self.VULN_TYPE_ALIASES.get(vt_lower, vt_lower)
            if canonical not in normalized:
                normalized.append(canonical)
        return normalized

    def _generate_subtasks(
        self, target: str, vuln_types: List[str]
    ) -> List[SubTask]:
        """
        Generate concrete sub-tasks from target and vulnerability types.

        Each vulnerability type on each major endpoint becomes a sub-task.
        """
        subtasks = []
        task_id = 0

        # Common endpoint patterns to test
        endpoint_types = {
            "sql_injection": ["login forms", "search endpoints", "ID parameters",
                            "filter/sort parameters", "API endpoints with database queries"],
            "xss": ["search fields", "comment forms", "user profile fields",
                   "URL parameters reflected in page", "error message parameters"],
            "ssrf": ["URL/fetch parameters", "webhook callbacks", "redirect parameters",
                    "proxy endpoints", "file import URLs"],
            "idor": ["user profile endpoints", "order/invoice endpoints",
                    "file download IDs", "API resource IDs"],
            "path_traversal": ["file include parameters", "template parameters",
                             "download endpoints", "static file serving"],
            "command_injection": ["ping/test endpoints", "admin utility endpoints",
                                "system status endpoints"],
            "csrf": ["state-changing forms", "password change", "email change",
                    "fund transfer / payment forms"],
            "open_redirect": ["login redirect parameters", "return/next URL parameters"],
            "information_disclosure": ["error pages", "debug endpoints",
                                      "API documentation", "hidden files/dirs"],
        }

        for vt in vuln_types:
            test_areas = endpoint_types.get(vt, ["all endpoints"])
            priority = self._default_priority(vt)

            for area in test_areas[:3]:  # Limit to top 3 areas per type
                task_id += 1
                subtasks.append(SubTask(
                    id=task_id,
                    description=f"Test {area} for {vt.replace('_', ' ')} vulnerabilities",
                    priority=priority,
                    vuln_type=vt,
                    target_endpoint=area,
                    estimated_effort="low" if "parameter" in area else "medium",
                ))

        # Sort by priority
        priority_order = {"high": 0, "medium": 1, "low": 2}
        subtasks.sort(key=lambda s: priority_order.get(s.priority, 1))

        return subtasks

    def _default_priority(self, vuln_type: str) -> str:
        """Get default priority for a vulnerability type."""
        high_priority = {
            "sql_injection", "command_injection", "deserialization",
            "ssti", "xxe",
        }
        medium_priority = {
            "xss", "ssrf", "idor", "path_traversal", "csrf",
            "open_redirect",
        }

        if vuln_type in high_priority:
            return "high"
        elif vuln_type in medium_priority:
            return "medium"
        return "low"

    def _identify_intervention_points(
        self,
        target: str,
        vuln_types: List[str],
        constraints: Dict,
        task_text: str,
    ) -> List[str]:
        """
        Identify scenarios that may require human intervention.

        These are pre-annotated points where the agent may need to pause
        and ask for human judgment.
        """
        points = []

        # Complex vulnerability chains
        if len(vuln_types) > 5:
            points.append("Large number of vulnerability types requested — "
                         "may need human prioritization")

        # Destructive testing requested
        if constraints.get("destructive_allowed"):
            points.append("Destructive testing requested — requires human approval "
                         "for each destructive operation")

        # Very large scope
        if constraints.get("max_depth", 0) > 5:
            points.append("Deep crawl depth requested — may need human "
                         "to narrow scope after initial findings")

        # Auth-dependent testing
        if "authentication" in task_text.lower() or "login" in task_text.lower():
            points.append("Authentication-required testing — human may need "
                         "to provide credentials or session tokens")

        # Binary/compiled targets
        if any(kw in task_text.lower() for kw in
               ["binary", "compiled", "assembly", "reverse engineer"]):
            points.append("Binary analysis requested — this is outside web "
                         "vulnerability scope, needs human specialist")

        # Business logic
        if "business logic" in task_text.lower():
            points.append("Business logic vulnerability assessment — "
                         "requires human domain knowledge")

        return points
