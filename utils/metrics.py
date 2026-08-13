"""
Metrics tracker for the SRC Vulnerability Mining Agent.

Tracks quantitative metrics across the entire pipeline:
- Vulnerability discovery rate
- False positive rate
- Code audit volume
- Time-to-find-high-severity
- LLM cost
- Human intervention time ratio
"""

import time
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path


@dataclass
class StepMetrics:
    """Metrics for a single pipeline step."""

    step_name: str
    start_time: float = 0.0
    end_time: float = 0.0
    input_count: int = 0
    output_count: int = 0
    llm_calls: int = 0
    llm_tokens_prompt: int = 0
    llm_tokens_completion: int = 0
    llm_cost_usd: float = 0.0
    human_intervention: bool = False
    human_wait_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return self.end_time - self.start_time if self.end_time > 0 else 0


class MetricsTracker:
    """
    Tracks quantitative metrics for the entire agent pipeline.

    Usage:
        tracker = MetricsTracker(task_id="task_001")
        tracker.start_step("info_collection")
        # ... do work ...
        tracker.end_step("info_collection", output_count=45)
        tracker.start_step("analysis")
        # ... do work ...
        tracker.end_step("analysis", output_count=12, llm_calls=3)
        report = tracker.generate_report()
    """

    def __init__(self, task_id: str = "unknown"):
        self.task_id = task_id
        self.task_start_time = time.time()
        self.task_end_time: Optional[float] = None
        self.steps: Dict[str, StepMetrics] = {}
        self._current_step: Optional[str] = None

        # Accumulated counters
        self.total_endpoints_scanned = 0
        self.total_code_lines_analyzed = 0
        self.total_suspicious_findings = 0
        self.total_confirmed_vulns = 0
        self.total_false_positives = 0
        self.total_uncertain = 0
        self.first_high_severity_time: Optional[float] = None
        self.human_intervention_start: Optional[float] = None
        self.total_human_wait_seconds: float = 0.0

    # --- Step tracking ---

    def start_step(self, step_name: str) -> None:
        """Mark the start of a pipeline step."""
        if step_name not in self.steps:
            self.steps[step_name] = StepMetrics(step_name=step_name)
        self.steps[step_name].start_time = time.time()
        self._current_step = step_name

    def end_step(
        self,
        step_name: str,
        input_count: int = 0,
        output_count: int = 0,
        llm_calls: int = 0,
        llm_tokens_prompt: int = 0,
        llm_tokens_completion: int = 0,
        llm_cost_usd: float = 0.0,
        error: Optional[str] = None,
    ) -> StepMetrics:
        """Mark the end of a pipeline step with outcome metrics."""
        if step_name not in self.steps:
            self.steps[step_name] = StepMetrics(step_name=step_name)
        step = self.steps[step_name]
        step.end_time = time.time()
        step.input_count = input_count
        step.output_count = output_count
        step.llm_calls += llm_calls
        step.llm_tokens_prompt += llm_tokens_prompt
        step.llm_tokens_completion += llm_tokens_completion
        step.llm_cost_usd += llm_cost_usd
        if error:
            step.errors.append(error)
        self._current_step = None
        return step

    def record_llm_call(
        self, step_name: str, prompt_tokens: int, completion_tokens: int, cost_usd: float
    ) -> None:
        """Record an LLM API call with token usage and cost."""
        if step_name not in self.steps:
            self.steps[step_name] = StepMetrics(step_name=step_name)
        step = self.steps[step_name]
        step.llm_calls += 1
        step.llm_tokens_prompt += prompt_tokens
        step.llm_tokens_completion += completion_tokens
        step.llm_cost_usd += cost_usd

    # --- Human intervention tracking ---

    def start_human_intervention(self) -> None:
        """Record the start of a human intervention period."""
        self.human_intervention_start = time.time()

    def end_human_intervention(self) -> None:
        """Record the end of a human intervention period."""
        if self.human_intervention_start is not None:
            wait = time.time() - self.human_intervention_start
            self.total_human_wait_seconds += wait
            if self._current_step and self._current_step in self.steps:
                self.steps[self._current_step].human_intervention = True
                self.steps[self._current_step].human_wait_seconds += wait
            self.human_intervention_start = None

    # --- Finding tracking ---

    def record_finding(
        self,
        verdict: str,  # "confirmed", "false_positive", "uncertain"
        severity: str = "medium",
        code_lines: int = 0,
    ) -> None:
        """Record a vulnerability finding with its classification."""
        self.total_suspicious_findings += 1
        if verdict == "confirmed":
            self.total_confirmed_vulns += 1
            # Track first high/critical finding time
            if severity in ("high", "critical") and self.first_high_severity_time is None:
                self.first_high_severity_time = time.time() - self.task_start_time
        elif verdict == "false_positive":
            self.total_false_positives += 1
        elif verdict == "uncertain":
            self.total_uncertain += 1
        self.total_code_lines_analyzed += code_lines

    # --- Report generation ---

    def finish_task(self) -> None:
        """Mark the overall task as complete."""
        self.task_end_time = time.time()

    @property
    def total_duration_seconds(self) -> float:
        end = self.task_end_time or time.time()
        return end - self.task_start_time

    def generate_report(self) -> dict:
        """
        Generate a comprehensive metrics report.

        Returns:
            dict with all quantitative metrics for the task
        """
        total_suspicious = max(self.total_suspicious_findings, 1)  # Avoid div by zero

        return {
            "task_id": self.task_id,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_duration_seconds": round(self.total_duration_seconds, 2),
                "total_endpoints_scanned": self.total_endpoints_scanned,
                "total_code_lines_analyzed": self.total_code_lines_analyzed,
                "total_suspicious_findings": self.total_suspicious_findings,
                "total_confirmed_vulns": self.total_confirmed_vulns,
                "total_false_positives": self.total_false_positives,
                "total_uncertain": self.total_uncertain,
            },
            "rates": {
                "vuln_detection_rate": round(
                    self.total_confirmed_vulns / total_suspicious, 4
                ),
                "false_positive_rate": round(
                    self.total_false_positives / total_suspicious, 4
                ),
                "uncertain_rate": round(
                    self.total_uncertain / total_suspicious, 4
                ),
            },
            "efficiency": {
                "time_to_first_high_severity_seconds": (
                    round(self.first_high_severity_time, 1)
                    if self.first_high_severity_time is not None
                    else None
                ),
                "avg_time_per_endpoint_seconds": (
                    round(self.total_duration_seconds / max(self.total_endpoints_scanned, 1), 2)
                ),
                "human_intervention_ratio": round(
                    self.total_human_wait_seconds / max(self.total_duration_seconds, 1), 4
                ),
            },
            "cost": {
                "total_llm_calls": sum(s.llm_calls for s in self.steps.values()),
                "total_llm_tokens_prompt": sum(s.llm_tokens_prompt for s in self.steps.values()),
                "total_llm_tokens_completion": sum(
                    s.llm_tokens_completion for s in self.steps.values()
                ),
                "total_llm_cost_usd": round(
                    sum(s.llm_cost_usd for s in self.steps.values()), 4
                ),
            },
            "step_details": {
                name: {
                    "duration_seconds": round(step.duration_seconds, 2),
                    "input_count": step.input_count,
                    "output_count": step.output_count,
                    "llm_calls": step.llm_calls,
                    "llm_cost_usd": round(step.llm_cost_usd, 4),
                    "human_intervention": step.human_intervention,
                    "errors": step.errors,
                }
                for name, step in self.steps.items()
            },
        }

    def save_report(self, output_dir: str = "output") -> str:
        """Save metrics report as JSON to the output directory."""
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)
        report = self.generate_report()
        filepath = path / f"metrics_{self.task_id}_{datetime.now():%Y%m%d_%H%M%S}.json"
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        return str(filepath)
