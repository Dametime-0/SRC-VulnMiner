"""
Session — 会话状态持久化（参考 vulnclaw 的 session JSON 设计）

每个任务一个会话JSON文件，包含：
- 目标与约束
- 阶段与轮次历史
- 漏洞发现（findings）
- 执行步骤（executed_steps）
- 关键事实（notes / confirmed_facts）

会话在每个轮次结束后自动保存，支持中断恢复。
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from utils.logger import get_logger

logger = get_logger("agent.session")


class AgentSession:
    """单个任务的会话状态。"""

    PHASES = ["task_parsing", "info_collection", "analysis", "verification", "reporting"]

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get("session", {})
        self.output_dir = Path(self.config.get("output_dir", "output"))
        self.session_dir = Path(self.config.get("session_dir", "sessions"))
        self.session_dir.mkdir(parents=True, exist_ok=True)

        self.task_id: str = ""
        self.target: str = ""
        self.phase: str = "task_parsing"
        self.started_at: str = ""
        self.round: int = 0

        # vulnclaw-style state
        self.findings: List[Dict[str, Any]] = []
        self.executed_steps: List[str] = []
        self.notes: List[str] = []
        self.constraints: Dict[str, Any] = {}
        self.constraint_violations: List[str] = []
        self.recon_data: Dict[str, Any] = {}
        self.confirmed_facts: List[str] = []

        # Metrics
        self.llm_calls: int = 0
        self.llm_tokens_prompt: int = 0
        self.llm_tokens_completion: int = 0
        self.llm_cost_usd: float = 0.0
        self.human_interventions: List[Dict] = []
        self.round_times: List[float] = []

    # --- 初始化 ---

    def init(self, task_id: str, target: str, constraints: Dict[str, Any]) -> None:
        """Initialize a new session for a task."""
        self.task_id = task_id
        self.target = target
        self.constraints = constraints
        self.phase = "task_parsing"
        self.round = 0
        self.started_at = datetime.now().isoformat()
        self.record_step("会话初始化", f"目标: {target}")

    # --- 阶段管理 ---

    def switch_phase(self, new_phase: str) -> None:
        """Switch to a new phase (with validation)."""
        if new_phase not in self.PHASES:
            logger.warning(f"Unknown phase '{new_phase}', staying in '{self.phase}'")
            return
        old_phase = self.phase
        self.phase = new_phase
        self.record_step(f"阶段切换: {old_phase} → {new_phase}", "")

    # --- 记录 ---

    def record_step(self, action: str, detail: str = "") -> None:
        """Record an executed step (vulnclaw-style)."""
        entry = action if not detail else f"{action}: {detail[:200]}"
        self.executed_steps.append(entry)

    def add_note(self, note: str) -> None:
        """Add a note to the session."""
        self.notes.append(note)

    def add_confirmed_fact(self, fact: str) -> None:
        """Add a confirmed fact (verified information)."""
        if fact not in self.confirmed_facts:
            self.confirmed_facts.append(fact)

    # --- Findings ---

    def add_finding(self, finding: Dict[str, Any]) -> str:
        """
        Add a vulnerability finding.

        vulnclaw-style finding schema:
        - title, severity, vuln_type, description
        - evidence, evidence_level (L1=L0+L1, L2=verified)
        - verification_status: pending / verified / failed / skipped
        """
        finding_id = finding.get("finding_id") or f"F{len(self.findings) + 1:03d}"
        finding["finding_id"] = finding_id
        finding.setdefault("severity", "medium")
        finding.setdefault("verification_status", "pending")
        finding.setdefault("evidence_level", "L1")
        finding.setdefault("found_round", self.round)
        finding.setdefault("phase", self.phase)

        # Dedup: same vuln_type + location = update instead of add
        for existing in self.findings:
            if (existing.get("vuln_type") == finding.get("vuln_type") and
                    existing.get("location") == finding.get("location")):
                original_id = existing.get("finding_id", finding_id)
                existing.update(finding)
                existing["finding_id"] = original_id  # 保留原始ID
                logger.info(f"Finding updated: {original_id} ({finding.get('title', '')})")
                return original_id

        self.findings.append(finding)
        logger.info(f"Finding added: {finding_id} [{finding.get('severity', '?')}] "
                    f"{finding.get('vuln_type', '?')} — {finding.get('title', '')[:60]}")
        return finding_id

    def mark_verified(self, finding_id: str, note: str = "") -> None:
        """Mark a finding as verified (L2 evidence)."""
        for f in self.findings:
            if f.get("finding_id") == finding_id:
                f["verification_status"] = "verified"
                f["evidence_level"] = "L2"
                if note:
                    f["verification_note"] = note
                return

    # --- LLM usage ---

    def record_llm_call(self, prompt_tokens: int, completion_tokens: int, cost_usd: float) -> None:
        self.llm_calls += 1
        self.llm_tokens_prompt += prompt_tokens
        self.llm_tokens_completion += completion_tokens
        self.llm_cost_usd += cost_usd

    def record_round_time(self, seconds: float) -> None:
        self.round_times.append(seconds)

    # --- 持久化 ---

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "target": self.target,
            "phase": self.phase,
            "round": self.round,
            "started_at": self.started_at,
            "constraints": self.constraints,
            "constraint_violations": self.constraint_violations,
            "findings": self.findings,
            "executed_steps": self.executed_steps,
            "notes": self.notes,
            "confirmed_facts": self.confirmed_facts,
            "recon_data": self.recon_data,
            "metrics": {
                "llm_calls": self.llm_calls,
                "llm_tokens_prompt": self.llm_tokens_prompt,
                "llm_tokens_completion": self.llm_tokens_completion,
                "llm_cost_usd": round(self.llm_cost_usd, 4),
                "round_times": [round(t, 2) for t in self.round_times],
            },
        }

    def save(self) -> str:
        """Save session to JSON file (auto-save after each round)."""
        if not self.task_id:
            return ""
        safe_target = self.target.replace("://", "_").replace("/", "_").replace(":", "_")[:60]
        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{self.task_id}_{safe_target}.json"
        filepath = self.session_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
        return str(filepath)

    # --- 报告摘要 ---

    def get_summary(self) -> Dict[str, Any]:
        verified = [f for f in self.findings if f.get("verification_status") == "verified"]
        return {
            "total_findings": len(self.findings),
            "verified": len(verified),
            "pending": sum(1 for f in self.findings if f.get("verification_status") == "pending"),
            "by_severity": {
                sev: sum(1 for f in self.findings if f.get("severity") == sev)
                for sev in ["critical", "high", "medium", "low", "info"]
            },
            "total_rounds": self.round,
            "llm_calls": self.llm_calls,
            "llm_cost_usd": round(self.llm_cost_usd, 4),
        }
