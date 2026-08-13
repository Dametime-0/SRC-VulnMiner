"""
Module 6: Reporter (结果汇总模块)

Generates structured, quantified reports from the agent's findings.

Outputs:
1. JSON report (range-compatible, machine-readable)
2. Markdown report (human-readable, with evidence and PoC details)

Key metrics calculated:
- Vulnerability detection rate
- False positive rate
- Code audit volume (lines/files/endpoints)
- Time to first high-severity finding
- LLM cost (calls, tokens, USD)
- Human intervention time ratio
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from utils.logger import get_logger

logger = get_logger("agent.reporter")


class Reporter:
    """
    Report generator for the SRC Vulnerability Mining Agent.

    Usage:
        reporter = Reporter(desensitizer, config)
        report = reporter.generate(task_id, parsed_task, inventory,
                                   candidates, triaged, verified, metrics)
        paths = reporter.save(report, "output/")
    """

    def __init__(self, desensitizer, config: Dict[str, Any]):
        """
        Initialize the reporter.

        Args:
            desensitizer: Desensitizer instance for data masking
            config: Full agent configuration
        """
        self.desensitizer = desensitizer
        self.config = config
        self.reporting_config = config.get("reporting", {})

    def generate(
        self,
        task_id: str,
        parsed_task: Dict[str, Any],
        inventory: Dict[str, Any],
        candidates: List[Dict],
        triaged: List[Dict],
        verified: List[Dict],
        metrics,
        uncertain_count: int = 0,
        interventions: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive report.

        Args:
            task_id: Task identifier
            parsed_task: Parsed task from TaskParser
            inventory: Asset inventory from InfoCollector
            candidates: Raw candidates from Analyzer
            triaged: Triaged findings from FilterJudge
            verified: Verified findings from Verifier
            metrics: MetricsTracker instance
            uncertain_count: Number of uncertain findings
            interventions: Intervention summary from BoundaryController

        Returns:
            Complete report dict (desensitized)
        """
        metrics_report = metrics.generate_report() if metrics else {}

        # Count findings by type
        by_type = self._count_by_type(verified)

        # Build verified findings list (desensitized)
        verified_list = []
        for f in verified:
            verified_list.append(self.desensitizer.sanitize_finding({
                "vuln_type": f.get("vuln_type", "unknown"),
                "severity": f.get("severity", "medium"),
                "confidence": f.get("confidence", 0),
                "title": f.get("title", "Untitled"),
                "location": f.get("location", ""),
                "verified": f.get("verified", False),
                "verification_evidence": f.get("verification_evidence", {}),
                "poc": f.get("verification_result", {}).get("evidence", {}),
                "description": f.get("description", ""),
                "llm_analysis": f.get("llm_analysis", ""),
            }))

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in verified_list:
            sev = f.get("severity", "medium")
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Build report
        report = {
            "meta": {
                "agent": "SRC-VulnMiner",
                "version": self.config.get("agent", {}).get("version", "1.0.0"),
                "task_id": task_id,
                "timestamp": datetime.now().isoformat(),
                "target": self.desensitizer.mask(parsed_task.get("target_url", "")),
                "vuln_types": parsed_task.get("vuln_types", []),
            },
            "summary": {
                "total_candidates": len(candidates),
                "total_triaged": len(triaged),
                "confirmed_vulns": sum(1 for t in triaged if t.get("verdict") == "confirmed"),
                "verified_vulns": sum(1 for v in verified if v.get("verified")),
                "false_positives": sum(1 for t in triaged if t.get("verdict") == "false_positive"),
                "uncertain": uncertain_count,
                "total_duration_seconds": round(metrics.total_duration_seconds, 1) if metrics else 0,
            },
            "rates": {
                "vuln_detection_rate": round(
                    sum(1 for t in triaged if t.get("verdict") == "confirmed") /
                    max(len(triaged), 1), 4
                ),
                "false_positive_rate": round(
                    sum(1 for t in triaged if t.get("verdict") == "false_positive") /
                    max(len(triaged), 1), 4
                ),
                "verification_rate": round(
                    sum(1 for v in verified if v.get("verified")) /
                    max(len(verified), 1), 4
                ) if verified else 0,
            },
            "efficiency": {
                "total_duration_seconds": round(metrics.total_duration_seconds, 1) if metrics else 0,
                "time_to_first_high_severity_s": (
                    metrics_report.get("efficiency", {}).get("time_to_first_high_severity_seconds")
                    if metrics else None
                ),
                "human_intervention_ratio": (
                    metrics_report.get("efficiency", {}).get("human_intervention_ratio", 0)
                    if metrics else 0
                ),
                "endpoints_scanned": inventory.get("stats", {}).get("total_endpoints", 0),
                "code_files_analyzed": len(inventory.get("files", [])),
                "code_lines_analyzed": sum(
                    f.get("line_count", 0) for f in inventory.get("files", [])
                ),
            },
            "cost_summary": {
                "llm_calls": metrics_report.get("cost", {}).get("total_llm_calls", 0) if metrics else 0,
                "llm_tokens_prompt": (
                    metrics_report.get("cost", {}).get("total_llm_tokens_prompt", 0)
                    if metrics else 0
                ),
                "llm_tokens_completion": (
                    metrics_report.get("cost", {}).get("total_llm_tokens_completion", 0)
                    if metrics else 0
                ),
                "llm_cost_usd": round(
                    metrics_report.get("cost", {}).get("total_llm_cost_usd", 0), 4
                ) if metrics else 0,
            },
            "findings_by_type": by_type,
            "findings_by_severity": severity_counts,
            "findings": verified_list,
            "inventory_summary": {
                "tech_stack": inventory.get("env", {}).get("tech_stack", []),
                "waf_detected": inventory.get("env", {}).get("waf", ""),
                "total_endpoints": inventory.get("stats", {}).get("total_endpoints", 0),
                "total_forms": inventory.get("stats", {}).get("total_forms", 0),
            },
            "interventions": interventions or {},
            "metrics": metrics_report,
        }

        # Apply desensitization to entire report
        report = self.desensitizer.sanitize_report(report)

        logger.info(f"Report generated: {report['summary']}")
        return report

    def save(self, report: Dict[str, Any], output_dir: str = "output") -> List[str]:
        """
        Save report in configured formats.

        Args:
            report: Report dict from generate()
            output_dir: Directory to save reports

        Returns:
            List of saved file paths
        """
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)

        task_id = report.get("meta", {}).get("task_id", "unknown")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved_paths = []

        formats = self.reporting_config.get("formats", ["json", "markdown"])

        # JSON report
        if "json" in formats:
            json_path = path / f"report_{task_id}_{timestamp}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            saved_paths.append(str(json_path))
            logger.info(f"JSON report saved: {json_path}")

        # Markdown report
        if "markdown" in formats:
            md_path = path / f"report_{task_id}_{timestamp}.md"
            md_content = self._render_markdown(report)
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(md_content)
            saved_paths.append(str(md_path))
            logger.info(f"Markdown report saved: {md_path}")

        return saved_paths

    def _render_markdown(self, report: Dict[str, Any]) -> str:
        """Render the report as Markdown."""
        meta = report.get("meta", {})
        summary = report.get("summary", {})
        rates = report.get("rates", {})
        efficiency = report.get("efficiency", {})
        cost = report.get("cost_summary", {})

        md = f"""# SRC Vulnerability Mining Agent — Report

## Task Info
- **Task ID**: {meta.get('task_id', 'N/A')}
- **Target**: {meta.get('target', 'N/A')}
- **Vulnerability Types**: {', '.join(meta.get('vuln_types', []))}
- **Timestamp**: {meta.get('timestamp', 'N/A')}

---

## Summary

| Metric | Value |
|--------|-------|
| Total Candidates | {summary.get('total_candidates', 0)} |
| Confirmed Vulnerabilities | {summary.get('confirmed_vulns', 0)} |
| Verified Vulnerabilities | {summary.get('verified_vulns', 0)} |
| False Positives | {summary.get('false_positives', 0)} |
| Uncertain | {summary.get('uncertain', 0)} |
| Total Duration | {summary.get('total_duration_seconds', 0):.1f}s |

## Rates

| Rate | Value |
|------|-------|
| Detection Rate | {rates.get('vuln_detection_rate', 0):.1%} |
| False Positive Rate | {rates.get('false_positive_rate', 0):.1%} |
| Verification Rate | {rates.get('verification_rate', 0):.1%} |

## Efficiency

| Metric | Value |
|--------|-------|
| Total Duration | {efficiency.get('total_duration_seconds', 0):.1f}s |
| Time to First High-Severity | {efficiency.get('time_to_first_high_severity_s', 'N/A')} |
| Human Intervention Ratio | {efficiency.get('human_intervention_ratio', 0):.1%} |
| Endpoints Scanned | {efficiency.get('endpoints_scanned', 0)} |
| Code Files Analyzed | {efficiency.get('code_files_analyzed', 0)} |
| Code Lines Analyzed | {efficiency.get('code_lines_analyzed', 0)} |

## Cost

| Metric | Value |
|--------|-------|
| LLM Calls | {cost.get('llm_calls', 0)} |
| Prompt Tokens | {cost.get('llm_tokens_prompt', 0):,} |
| Completion Tokens | {cost.get('llm_tokens_completion', 0):,} |
| **Total Cost** | **${cost.get('llm_cost_usd', 0):.4f}** |

## Findings by Severity

| Severity | Count |
|----------|-------|
"""
        for sev, count in report.get("findings_by_severity", {}).items():
            md += f"| {sev.capitalize()} | {count} |\n"

        md += f"""
## Findings by Type

| Type | Count |
|------|-------|
"""
        for vtype, count in report.get("findings_by_type", {}).items():
            md += f"| {vtype.replace('_', ' ').title()} | {count} |\n"

        md += """
---

## Verified Findings

"""
        findings = report.get("findings", [])
        if not findings:
            md += "*No vulnerabilities were verified.*\n\n"
        else:
            for i, f in enumerate(findings, 1):
                verified_icon = "✅" if f.get("verified") else "❌"
                md += f"""### {i}. {verified_icon} {f.get('title', 'Untitled')}

- **Type**: {f.get('vuln_type', 'unknown').replace('_', ' ').title()}
- **Severity**: {f.get('severity', 'medium').upper()}
- **Confidence**: {f.get('confidence', 0):.0%}
- **Location**: `{f.get('location', 'N/A')}`
- **Verified**: {f.get('verified', False)}

**Description**: {f.get('description', 'No description available.')}

"""
                if f.get("llm_analysis"):
                    md += f"**LLM Analysis**: {f.get('llm_analysis', '')}\n\n"

                evidence = f.get("verification_evidence", {})
                if evidence:
                    md += f"""<details>
<summary>Verification Evidence</summary>

```json
{json.dumps(evidence, indent=2, ensure_ascii=False)[:2000]}
```
</details>

"""

        md += """
---

## Inventory Summary

- **Tech Stack**: """ + ", ".join(report.get("inventory_summary", {}).get("tech_stack", [])) + """
- **WAF Detected**: """ + str(report.get("inventory_summary", {}).get("waf_detected", "None")) + """
- **Endpoints**: """ + str(report.get("inventory_summary", {}).get("total_endpoints", 0)) + """
- **Forms**: """ + str(report.get("inventory_summary", {}).get("total_forms", 0)) + """

---

## Interventions

"""
        interventions = report.get("interventions", {})
        if interventions.get("total_interventions", 0) > 0:
            md += f"Total interventions requested: **{interventions.get('total_interventions', 0)}**\n\n"
            for detail in interventions.get("details", []):
                md += f"- **{detail.get('severity', '')}**: {detail.get('reason', '')}\n"
                if detail.get("suggestion"):
                    md += f"  → {detail.get('suggestion', '')}\n"
        else:
            md += "*No human intervention was required.*\n"

        md += """
---

*Report generated by SRC-VulnMiner. All data has been desensitized.*
"""
        return md

    # --- Helper ---

    def _count_by_type(self, findings: List[Dict]) -> Dict[str, int]:
        """Count verified findings by vulnerability type."""
        counts: Dict[str, int] = {}
        for f in findings:
            if f.get("verified"):
                vt = f.get("vuln_type", "unknown")
                counts[vt] = counts.get(vt, 0) + 1
        return counts
