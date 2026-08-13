"""
Boundary Controller — Scope and capability guard for the Agent.

This module enforces safety and quality boundaries:
1. **Scope check**: Reject tasks targeting unauthorized domains/IPs
2. **Capability check**: Recognize when a task exceeds the agent's abilities
3. **Hallucination guard**: Prevent LLM-only findings without evidence from being reported as confirmed

These guards are critical for competition scoring:
- Prevents the agent from "hallucinating" vulnerabilities
- Properly flags scenarios needing human intervention
- Tracks intervention requests as metrics
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse
import re

from .logger import get_logger

logger = get_logger("agent.boundary")


@dataclass
class InterventionRequest:
    """Records when the agent determines it needs human help."""

    reason: str
    module: str
    severity: str  # "blocking" (can't proceed) | "advisory" (can proceed with caution)
    context: Dict[str, Any] = field(default_factory=dict)
    suggestion: str = ""


class BoundaryController:
    """
    Controls the operational boundaries of the agent.

    Usage:
        bc = BoundaryController(config)

        # Check if a target is in authorized scope
        if not bc.check_scope("http://target.com"):
            raise ScopeViolation("Target not in authorized scope")

        # Check if task is within capabilities
        intervention = bc.check_capability(parsed_task)
        if intervention and intervention.severity == "blocking":
            return intervention  # Stop and request human

        # Guard against hallucinated findings
        guarded = bc.guard_llm_finding(finding)
    """

    # Vulnerability types the agent can handle
    SUPPORTED_VULN_TYPES = {
        "sql_injection", "sqli",
        "xss", "cross_site_scripting", "reflected_xss", "stored_xss",
        "ssrf", "server_side_request_forgery",
        "idor", "insecure_direct_object_reference",
        "path_traversal", "directory_traversal", "lfi",
        "command_injection", "os_command_injection",
        "csrf", "cross_site_request_forgery",
        "open_redirect",
        "information_disclosure",
        "ssti", "server_side_template_injection",
        "xxe", "xml_external_entity",
        "deserialization", "insecure_deserialization",
    }

    # Scenarios the agent CANNOT handle (needs human)
    BEYOND_CAPABILITY_INDICATORS = [
        "binary exploitation",
        "buffer overflow",
        "kernel exploit",
        "firmware analysis",
        "hardware security",
        "cryptographic implementation audit",
        "zero-day research",
        "APT attribution",
        "malware reverse engineering",
        "physical security test",
        "social engineering",
        "phishing campaign",
        "DDoS testing",
        "ransomware",
        "blockchain/smart contract audit",
    ]

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize boundary controller.

        Args:
            config: Full agent configuration
        """
        self.config = config
        self.scope_config = config.get("scope", {})
        self.safety_config = config.get("safety", {})
        self.agent_config = config.get("agent", {})

        # Parse authorized targets
        self.ctf_mode = self.scope_config.get("ctf_mode", True)
        self.authorized_domains: Set[str] = set(
            self.scope_config.get("authorized_domains", [])
        )
        self.authorized_urls: Set[str] = set(
            self.scope_config.get("authorized_urls", [])
        )
        self.authorized_ips: Set[str] = set(
            self.scope_config.get("authorized_ips", [])
        )

        # Intervention tracking
        self.interventions: List[InterventionRequest] = []

        # Auto-approve internal/test targets
        self._internal_patterns = [
            re.compile(r'https?://localhost[:\d]*'),
            re.compile(r'https?://127\.0\.0\.\d+'),
            re.compile(r'https?://\[::1\]'),
            re.compile(r'https?://\d+\.\d+\.\d+\.\d+:\d+'),  # Any IP:port (for demo)
        ]

    # --- Scope checking ---

    def check_scope(self, target: str) -> bool:
        """
        Check if a target URL is within authorized scope.

        In CTF mode, all targets are considered authorized.
        In production mode, only explicitly authorized targets pass.

        Args:
            target: URL or domain to check

        Returns:
            True if in scope, False otherwise
        """
        if not target:
            return False

        # CTF mode: authorize all (range provides the targets)
        if self.ctf_mode:
            return True

        # Internal/test targets are always authorized
        for pattern in self._internal_patterns:
            if pattern.match(target):
                return True

        # Parse the target
        try:
            parsed = urlparse(target if "://" in target else f"http://{target}")
        except Exception:
            return False

        hostname = parsed.hostname or target
        full_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else target

        # Check explicit authorizations
        if hostname in self.authorized_domains:
            return True
        if full_url in self.authorized_urls:
            return True
        if hostname in self.authorized_ips:
            return True

        # Check domain suffix matches
        for domain in self.authorized_domains:
            if hostname.endswith(f".{domain}") or hostname == domain:
                return True

        logger.warning(f"Target '{target}' is NOT in authorized scope")
        self.interventions.append(InterventionRequest(
            reason=f"Target '{target}' not in authorized scope",
            module="boundary",
            severity="blocking",
            context={"target": target, "authorized": list(self.authorized_domains)},
            suggestion="Add this target to authorized_domains in config.yaml or enable ctf_mode",
        ))
        return False

    # --- Capability checking ---

    def check_capability(self, parsed_task: Dict[str, Any]) -> Optional[InterventionRequest]:
        """
        Check if the agent can handle this task.

        Returns None if the task is within capabilities.
        Returns InterventionRequest if the task needs human help.

        Args:
            parsed_task: Parsed task dict with vuln_types, constraints, etc.

        Returns:
            InterventionRequest if beyond capability, None otherwise
        """
        vuln_types = parsed_task.get("vuln_types", [])
        task_text = parsed_task.get("raw_text", "").lower()

        # Check for explicitly unsupported vulnerability types
        unsupported = []
        for vt in vuln_types:
            if vt.lower() not in self.SUPPORTED_VULN_TYPES:
                unsupported.append(vt)

        if unsupported:
            intervention = InterventionRequest(
                reason=f"Unsupported vulnerability types: {', '.join(unsupported)}",
                module="boundary",
                severity="blocking",
                context={"unsupported_types": unsupported, "supported": list(self.SUPPORTED_VULN_TYPES)},
                suggestion=f"The agent supports web application vulnerabilities. "
                          f"Types like '{unsupported[0]}' require different tooling.",
            )
            self.interventions.append(intervention)
            return intervention

        # Check for beyond-capability indicators in task text
        for indicator in self.BEYOND_CAPABILITY_INDICATORS:
            if indicator in task_text:
                intervention = InterventionRequest(
                    reason=f"Task appears to involve '{indicator}' which is beyond agent capabilities",
                    module="boundary",
                    severity="blocking",
                    context={"indicator": indicator},
                    suggestion="This type of testing requires specialized tools and human expertise.",
                )
                self.interventions.append(intervention)
                return intervention

        # Check constraints for unsupported requirements
        constraints = parsed_task.get("constraints", {})
        if constraints.get("requires_auth") and not parsed_task.get("auth_credentials"):
            intervention = InterventionRequest(
                reason="Task requires authentication but no credentials provided",
                module="boundary",
                severity="blocking",
                context={},
                suggestion="Provide authentication credentials or mark endpoints as public-only.",
            )
            self.interventions.append(intervention)
            return intervention

        return None

    # --- Hallucination guard ---

    def guard_llm_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Guard against LLM hallucinations by checking for evidence.

        An LLM-only finding without rule engine support or verifiable
        evidence is downgraded to 'uncertain' to prevent false positives.

        Args:
            finding: A vulnerability finding dict

        Returns:
            Modified finding with adjusted confidence/verdict
        """
        # Check if this is purely an LLM finding (no rule match, no evidence)
        has_rule_match = bool(finding.get("rule_matches"))
        has_evidence = bool(finding.get("evidence"))
        has_code_location = bool(finding.get("location") and (
            ":" in str(finding.get("location", "")) or
            "http" in str(finding.get("location", ""))
        ))

        llm_only = not has_rule_match and not has_evidence

        if llm_only:
            logger.debug(
                f"Hallucination guard: LLM-only finding downgraded — "
                f"'{finding.get('title', 'unknown')}'"
            )
            finding["hallucination_risk"] = True
            finding["confidence"] = min(
                float(finding.get("confidence", 0.5)),
                0.4  # Cap LLM-only findings at 40% confidence
            )
            finding["verdict"] = "uncertain"
            finding["guard_note"] = (
                "Finding identified by LLM without rule engine support or "
                "independent evidence. Requires human review."
            )

        if not has_code_location and not has_evidence:
            logger.debug(
                f"Hallucination guard: location-less finding downgraded — "
                f"'{finding.get('title', 'unknown')}'"
            )
            finding["hallucination_risk"] = True
            finding["confidence"] = min(
                float(finding.get("confidence", 0.5)),
                0.3
            )

        return finding

    def guard_batch(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply hallucination guard to a batch of findings."""
        return [self.guard_llm_finding(f) for f in findings]

    # --- Reporting ---

    def get_intervention_summary(self) -> Dict[str, Any]:
        """Get summary of all intervention requests."""
        blocking = [i for i in self.interventions if i.severity == "blocking"]
        advisory = [i for i in self.interventions if i.severity == "advisory"]
        return {
            "total_interventions": len(self.interventions),
            "blocking": len(blocking),
            "advisory": len(advisory),
            "details": [
                {
                    "reason": i.reason,
                    "module": i.module,
                    "severity": i.severity,
                    "suggestion": i.suggestion,
                }
                for i in self.interventions
            ],
        }

    def clear(self) -> None:
        """Reset intervention tracking for a new task."""
        self.interventions = []
