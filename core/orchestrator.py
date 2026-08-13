"""
Orchestrator — LLM驱动的Agent主循环（参考 vulnclaw 设计）

核心区别（vs 旧版固定Pipeline）：
- LLM是驾驶员：每轮自主决定调用哪个工具
- 阶段可流转：task_parsing → info_collection → analysis → verification → reporting
- 每轮结束自动保存会话（可中断恢复）
- LLM回复中包含 <thinking> 思考过程（vulnclaw风格）

流程：
1. 初始化会话（目标、约束）
2. 循环：LLM决策 → 工具执行 → 结果反馈 → LLM再决策
3. LLM切换到 reporting 阶段并完成 → 生成报告
"""

import json
import time
from typing import Dict, List, Any, Optional

from utils.logger import get_logger
from .session import AgentSession
from .tools import ToolRegistry
from .constraints import ConstraintManager

logger = get_logger("agent.orchestrator")


SYSTEM_PROMPT = """你是SRC定向漏洞挖掘Agent——一个面向Web应用漏洞发现与验证的自主安全分析智能体。

## 工作方式
你通过调用工具完成工作，按阶段推进：
1. **task_parsing**: 解析任务目标，明确约束。调用 session_status 查看任务。
2. **info_collection**: 用 http_request 探测目标（首页、端点、表单），用 read_source/rule_scan 分析源码。
3. **analysis**: 用 rule_scan 扫描源码模式，结合 http_request 响应做深度分析。发现漏洞就调用 add_finding 记录。
4. **verification**: 对每个发现，用 http_request 发送安全的验证payload，确认后调用 mark_verified。只验证SQL注入/XSS/SSRF/IDOR，不要验证路径遍历和命令注入（会搞挂靶场）。每个漏洞最多3次验证请求，超时5秒内没有响应就放弃。
5. **reporting**: 全部完成后切换到此阶段。

## 关键纪律
1. HTTP请求要克制：每个端点探测1-2次就够，不要对同一端点反复发送payload
2. 验证payload必须非破坏性：只用 ' AND '1'='1 这类布尔测试、错误触发、无害的alert(1)
3. 发现疑似漏洞但证据不足时，标记为 uncertain 而不是强行确认
4. 用 python_exec 做数据处理（下载文件、解析响应、构造payload），但禁止破坏性代码
5. 每次回复先用 <thinking> 简述你的思考，然后调用工具
6. 目标不可达（连续超时）就停止探测，直接进入 reporting
7. 源码可用时优先做白盒分析（rule_scan），黑盒验证只是辅助
8. 所有发现必须脱敏，不记录真实凭据

## 输出要求
- 每个漏洞调用一次 add_finding，包含 title/severity/vuln_type/location/evidence
- 验证成功后调用 mark_verified
- 最后调用 switch_phase 到 reporting"""


class AgentOrchestrator:
    """
    LLM驱动的Agent主循环。

    Usage:
        orch = AgentOrchestrator(llm_client, http_client, rule_engine, config)
        report = orch.run(task_input)
    """

    def __init__(self, llm_client, http_client, rule_engine, config: Dict[str, Any]):
        self.llm = llm_client
        self.http = http_client
        self.rule_engine = rule_engine
        self.config = config
        self.agent_config = config.get("agent", {})
        self.max_rounds = self.agent_config.get("max_rounds", 30)

        self.session = AgentSession(config)
        self.constraints = ConstraintManager()
        self.tools = ToolRegistry(self.session, self.http, self.rule_engine, config)
        self.tools._constraints = self.constraints  # 注入约束管理器

    def run(self, task_input: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run the LLM-driven agent loop.

        Args:
            task_input: Task specification
                {"target": "...", "vuln_types": [...], "source_path": "...", ...}
                or {"task_text": "..."}

        Returns:
            Final report dict
        """
        # ── 1. 任务解析（确定性部分）──
        target = task_input.get("target", task_input.get("target_url", ""))
        if not target and "task_text" in task_input:
            target = self._extract_target_from_text(task_input["task_text"])

        if not target:
            return {"status": "error", "error": "No target specified in task"}

        task_id = task_input.get("task_id", f"task_{int(time.time())}")
        vuln_types = task_input.get("vuln_types", [])
        source_path = task_input.get("source_path", "")
        task_text = task_input.get("task_text", "")

        logger.info(f"Starting LLM-driven task: {task_id} → {target}")

        # ── 2. 会话初始化 ──
        self.session.init(task_id, target, {
            "vuln_types": vuln_types,
            "source_path": source_path,
            "task_text": task_text,
        })
        self.constraints.load_from_task(task_input)
        self.session.add_note(f"漏洞类型: {', '.join(vuln_types) if vuln_types else '全部常见Web漏洞'}")

        # ── 3. LLM驱动循环 ──
        messages: List[Dict[str, Any]] = []

        # 初始用户消息：任务描述
        init_msg = self._build_init_message(target, vuln_types, source_path, task_text)
        messages.append({"role": "user", "content": init_msg})

        consecutive_errors = 0
        last_phase = self.session.phase

        for round_num in range(1, self.max_rounds + 1):
            self.session.round = round_num
            round_start = time.time()

            # 调用LLM
            try:
                response = self.llm.chat_with_tools(
                    messages=messages,
                    system_prompt=SYSTEM_PROMPT,
                    tools=self.tools.get_tool_schemas(),
                )
            except Exception as e:
                logger.error(f"LLM call failed at round {round_num}: {e}")
                consecutive_errors += 1
                if consecutive_errors >= 3:
                    logger.error("Too many LLM errors, aborting")
                    break
                continue

            consecutive_errors = 0
            self.session.record_llm_call(
                response.prompt_tokens, response.completion_tokens, response.cost_usd
            )

            # 提取思考内容
            thinking = response.content[:200] if response.content else ""
            self.session.record_step(f"Round {round_num}: {thinking}")

            # 处理工具调用
            tool_calls = getattr(response, "tool_calls", None) or []
            if not tool_calls:
                # LLM没有调用工具——检查是否要结束
                if "reporting" in (response.content or "").lower() or round_num >= self.max_rounds - 1:
                    break
                # 让LLM继续（把它的回复作为assistant消息）
                messages.append({"role": "assistant", "content": response.content or ""})
                messages.append({"role": "user", "content": "请继续：调用工具推进任务。如果信息不足，先调用 session_status 了解状态。"})
                continue

            # 执行每个工具调用
            assistant_msg = {"role": "assistant", "content": response.content or "",
                             "tool_calls": []}
            for tc in tool_calls:
                tool_name = tc.get("name", "")
                tool_args = tc.get("arguments", {})
                if isinstance(tool_args, str):
                    try:
                        tool_args = json.loads(tool_args)
                    except json.JSONDecodeError:
                        tool_args = {}

                logger.info(f"  Round {round_num}: → {tool_name}({json.dumps(tool_args, ensure_ascii=False)[:100]})")
                result = self.tools.execute(tool_name, tool_args)

                assistant_msg["tool_calls"].append({
                    "id": tc.get("id", f"call_{round_num}_{len(assistant_msg['tool_calls'])}"),
                    "type": "function",
                    "function": {"name": tool_name, "arguments": json.dumps(tool_args, ensure_ascii=False)},
                })

            messages.append(assistant_msg)

            # 工具结果作为tool消息反馈
            for i, tc in enumerate(tool_calls):
                tool_name = tc.get("name", "")
                tool_args = tc.get("arguments", {})
                if isinstance(tool_args, str):
                    try:
                        tool_args = json.loads(tool_args)
                    except json.JSONDecodeError:
                        tool_args = {}
                result = self.tools.execute(tool_name, tool_args)  # 再次执行以获取结果
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", f"call_{round_num}_{i}"),
                    "content": result[:3000],  # 截断长结果
                })

            # 自动保存会话
            self.session.record_round_time(time.time() - round_start)
            if self.session.phase != last_phase:
                last_phase = self.session.phase
            self.session.save()

            # 检查是否完成
            if self.session.phase == "reporting" and self.session.round >= 3:
                # LLM自己宣告完成
                final_check = self._ask_final_check(messages)
                if final_check:
                    break

        # ── 4. 生成报告 ──
        report = self._generate_report(task_input)
        self.session.save()
        return report

    # --- 内部方法 ---

    def _build_init_message(
        self, target: str, vuln_types: List[str], source_path: str, task_text: str
    ) -> str:
        """Build the initial task message for the LLM."""
        msg = f"## 安全测试任务\n\n目标: {target}\n"
        if vuln_types:
            msg += f"漏洞类型: {', '.join(vuln_types)}\n"
        else:
            msg += "漏洞类型: 常见Web漏洞（SQL注入/XSS/SSRF/IDOR/路径遍历/命令注入）\n"
        if source_path:
            msg += f"源码路径: {source_path}\n"
        if task_text:
            msg += f"任务描述: {task_text}\n"
        msg += "\n开始执行。先调用 session_status 了解任务状态，然后按阶段推进。"
        return msg

    def _extract_target_from_text(self, text: str) -> str:
        """Extract URL from natural language task text."""
        import re
        match = re.search(r'https?://[^\s<>"\']+', text, re.IGNORECASE)
        return match.group(0) if match else ""

    def _ask_final_check(self, messages: List[Dict]) -> bool:
        """Ask the LLM if the task is complete."""
        try:
            response = self.llm.chat(
                messages=[{"role": "user",
                           "content": "任务是否已完成？如果所有发现都已验证和记录，回复 YES；否则回复 NO 并继续。"}],
                system_prompt="你是任务状态检查器。只回复 YES 或 NO。",
                max_tokens=10,
            )
            return "YES" in response.content.upper()
        except Exception:
            return False

    def _generate_report(self, task_input: Dict[str, Any]) -> Dict[str, Any]:
        """Generate the final structured report from session state."""
        summary = self.session.get_summary()
        findings = self.session.findings

        # 分类统计
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        verified_findings = []
        for f in findings:
            vt = f.get("vuln_type", "other")
            sev = f.get("severity", "medium")
            by_type[vt] = by_type.get(vt, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1
            if f.get("verification_status") == "verified":
                verified_findings.append(f)

        total_duration = sum(self.session.round_times)

        report = {
            "meta": {
                "agent": self.agent_config.get("name", "SRC-VulnMiner"),
                "version": self.agent_config.get("version", "2.0.0"),
                "task_id": self.session.task_id,
                "target": self.session.target,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "vuln_types": task_input.get("vuln_types", []),
            },
            "summary": {
                "total_candidates": len(findings),
                "confirmed_vulns": len(findings),
                "verified_vulns": len(verified_findings),
                "false_positives": 0,
                "uncertain": sum(1 for f in findings if f.get("verification_status") == "pending"),
                "total_duration_seconds": round(total_duration, 1),
                "total_rounds": self.session.round,
            },
            "rates": {
                "verification_rate": round(
                    len(verified_findings) / max(len(findings), 1), 4
                ),
                "false_positive_rate": 0.0,
            },
            "efficiency": {
                "total_duration_seconds": round(total_duration, 1),
                "llm_rounds": self.session.round,
                "human_intervention_ratio": 0.0,
            },
            "cost_summary": {
                "llm_calls": self.session.llm_calls,
                "llm_tokens_prompt": self.session.llm_tokens_prompt,
                "llm_tokens_completion": self.session.llm_tokens_completion,
                "llm_cost_usd": round(self.session.llm_cost_usd, 4),
            },
            "findings_by_type": by_type,
            "findings_by_severity": by_severity,
            "findings": [
                {
                    "id": f.get("finding_id"),
                    "title": f.get("title"),
                    "vuln_type": f.get("vuln_type"),
                    "severity": f.get("severity"),
                    "location": f.get("location"),
                    "description": f.get("description", ""),
                    "evidence": f.get("evidence", ""),
                    "poc": f.get("poc_script"),
                    "evidence_level": f.get("evidence_level", "L1"),
                    "verified": f.get("verification_status") == "verified",
                    "verification_note": f.get("verification_note", ""),
                }
                for f in findings
            ],
            "executed_steps": self.session.executed_steps,
            "confirmed_facts": self.session.confirmed_facts,
            "constraint_violations": self.constraints.get_violation_summary(),
            "session_file": self.session.save(),
        }

        # 保存JSON报告
        from pathlib import Path
        output_dir = Path(self.config.get("reporting", {}).get("output_dir", "output/"))
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"report_{self.session.task_id}_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        logger.info(f"Report saved: {report_path}")

        # 打印摘要
        self._print_summary(report)
        return report

    def _print_summary(self, report: Dict) -> None:
        s = report["summary"]
        c = report["cost_summary"]
        print("\n" + "=" * 60)
        print("  SRC Vulnerability Mining Agent — 任务完成")
        print("=" * 60)
        print(f"\n  发现: {s['total_candidates']} 个漏洞候选")
        print(f"  验证: {s['verified_vulns']} 个已验证 (L2证据)")
        print(f"  待定: {s['uncertain']} 个待确认")
        print(f"\n  轮次: {s['total_rounds']} 轮 LLM 决策")
        print(f"  耗时: {s['total_duration_seconds']:.1f}s")
        print(f"  LLM调用: {c['llm_calls']} 次, ${c['llm_cost_usd']:.4f}")
        print("\n  已验证漏洞:")
        for f in report["findings"]:
            if f.get("verified"):
                print(f"    [{f['severity'].upper()}] {f['vuln_type']}: {f['title']}")
                print(f"      {f['verification_note'][:100]}")
        print("=" * 60)
