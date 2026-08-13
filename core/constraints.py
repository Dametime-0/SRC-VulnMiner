"""
Constraints — 任务约束管理（参考 vulnclaw 的 task_constraints 设计）

约束类型：
- allowed_hosts / blocked_hosts: 目标主机白名单/黑名单
- allowed_actions / blocked_actions: 允许/禁止的操作
- strict_mode: 严格模式下，任何越界行为都被记录并阻止
"""

from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger("agent.constraints")


class ConstraintManager:
    """Manages and enforces task constraints."""

    def __init__(self):
        self.allowed_hosts: List[str] = []
        self.blocked_hosts: List[str] = []
        self.allowed_actions: List[str] = []
        self.blocked_actions: List[str] = [
            # 默认禁止的破坏性操作
            "DROP", "DELETE FROM", "TRUNCATE", "UPDATE", "INSERT",
            "rm -rf", "shutdown", "reboot", "dd if=",
        ]
        self.strict_mode: bool = True
        self.notes: List[str] = []
        self.violations: List[Dict] = []

    def load_from_task(self, task: Dict[str, Any]) -> None:
        """Load constraints from a task specification."""
        constraints = task.get("constraints", {})

        if "destructive_allowed" in constraints:
            if not constraints["destructive_allowed"]:
                self.blocked_actions.extend([
                    "DROP", "DELETE FROM", "TRUNCATE", "UPDATE", "INSERT",
                ])

        # Scope constraints
        scope = task.get("scope", [])
        if scope:
            for s in scope:
                host = self._extract_host(s)
                if host:
                    self.allowed_hosts.append(host)

        self.strict_mode = constraints.get("strict_mode", True)
        self.notes = constraints.get("notes", [])

        # Add the target to allowed hosts
        target = task.get("target", task.get("target_url", ""))
        if target:
            host = self._extract_host(target)
            if host and host not in self.allowed_hosts:
                self.allowed_hosts.append(host)

    def check_host(self, url: str) -> bool:
        """
        Check if a URL's host is within allowed scope.

        Returns False and records a violation if out of scope.
        """
        host = self._extract_host(url)
        if not host:
            return False

        # No restrictions → allow
        if not self.allowed_hosts:
            return True

        for allowed in self.allowed_hosts:
            if host == allowed or host.endswith(f".{allowed}") or allowed == "localhost":
                return True

        # 127.0.0.1 and localhost always allowed for demo/testing
        if host in ("127.0.0.1", "localhost", "::1"):
            return True

        violation = {"type": "out_of_scope_host", "host": host, "url": url}
        self.violations.append(violation)
        logger.warning(f"Constraint violation: out-of-scope host '{host}'")
        return False

    def check_action(self, action: str) -> bool:
        """
        Check if an action (code/PoC) contains blocked operations.
        """
        action_upper = action.upper()
        for blocked in self.blocked_actions:
            if blocked.upper() in action_upper:
                violation = {"type": "blocked_action", "action": blocked}
                self.violations.append(violation)
                logger.warning(f"Constraint violation: blocked action '{blocked}'")
                return False
        return True

    def _extract_host(self, url: str) -> str:
        """Extract hostname from a URL."""
        if not url:
            return ""
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            return parsed.hostname or ""
        except Exception:
            return ""

    def get_violation_summary(self) -> Dict[str, Any]:
        return {
            "total_violations": len(self.violations),
            "violations": self.violations[:10],
        }
