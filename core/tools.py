"""
Tools — LLM可调用的工具层

工具是LLM的"手"。LLM通过function-calling调用这些工具：
1. http_request — HTTP请求（硬超时、零重试，绝不死循环）
2. python_exec — Python代码执行（审计记录，用于数据处理/构造payload）
3. rule_scan — 规则引擎扫描（确定性的漏洞模式匹配）
4. add_finding — 记录漏洞发现
5. mark_verified — 标记漏洞已验证
6. switch_phase — 切换阶段
7. read_source — 读取源码文件
"""

import json
import time
import traceback
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable

from utils.logger import get_logger

logger = get_logger("agent.tools")


class ToolRegistry:
    """
    Tool registry — executes tool calls from the LLM.

    Usage:
        registry = ToolRegistry(session, http_client, rule_engine, config)
        result = registry.execute("http_request", {"method": "GET", "url": "..."})
    """

    def __init__(self, session, http_client, rule_engine, config: Dict[str, Any]):
        self.session = session
        self.http = http_client
        self.rule_engine = rule_engine
        self.config = config
        self.tool_config = config.get("tools", {})

        # Python execution audit log
        self.python_audit: List[Dict] = []
        self.audit_path = Path("output/python_execute_audit.jsonl")

        # Tool registry: name → (function, description)
        self._tools: Dict[str, Callable] = {
            "http_request": self.http_request,
            "python_exec": self.python_exec,
            "rule_scan": self.rule_scan,
            "add_finding": self.add_finding,
            "mark_verified": self.mark_verified,
            "switch_phase": self.switch_phase,
            "read_source": self.read_source,
            "session_status": self.session_status,
        }

    # --- 工具定义（供LLM function-calling使用）---

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        """Return OpenAI-style tool schemas for LLM function calling."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "http_request",
                    "description": "发送HTTP请求到目标（GET/POST/HEAD），返回状态码、响应头和正文（截断）。"
                                   "超时10秒，不重试。用于端点探测、表单测试、漏洞验证。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "method": {"type": "string", "enum": ["GET", "POST", "HEAD"]},
                            "url": {"type": "string", "description": "完整URL，如 http://target/login"},
                            "params": {"type": "object", "description": "查询参数（GET）或表单数据（POST），JSON对象"},
                            "headers": {"type": "object", "description": "额外请求头"},
                        },
                        "required": ["method", "url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "python_exec",
                    "description": "执行Python代码（受信本地执行）。用于：下载/解压文件、构造payload、"
                                   "解析数据、正则匹配、数据处理。禁止破坏性操作。超时20秒。"
                                   "代码中用print()输出结果。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "code": {"type": "string", "description": "要执行的Python代码"},
                            "purpose": {"type": "string", "description": "这次执行的目的（用于审计）"},
                        },
                        "required": ["code", "purpose"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "rule_scan",
                    "description": "对目标源码运行规则引擎扫描。返回匹配的漏洞模式（危险函数调用、"
                                   "用户输入来源、SQL拼接等）。这是确定性扫描，结果可信。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "source_path": {"type": "string", "description": "源码目录路径（本地）"},
                        },
                        "required": ["source_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "add_finding",
                    "description": "记录一个漏洞发现到会话。每发现一个真实漏洞就调用一次。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string", "description": "漏洞标题（简短）"},
                            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                            "vuln_type": {"type": "string", "description": "漏洞类型：sql_injection/xss/ssrf/idor/path_traversal/command_injection/other"},
                            "description": {"type": "string", "description": "技术细节描述"},
                            "location": {"type": "string", "description": "位置：文件:行号 或 URL?参数"},
                            "evidence": {"type": "string", "description": "证据：代码片段、HTTP响应特征等"},
                            "poc": {"type": "string", "description": "PoC/复现步骤（可选）"},
                        },
                        "required": ["title", "severity", "vuln_type", "location", "evidence"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "mark_verified",
                    "description": "标记一个漏洞已被实际验证（L2证据级）。只在实际发送payload并确认后调用。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "finding_id": {"type": "string", "description": "漏洞ID（如F001）"},
                            "note": {"type": "string", "description": "验证说明：用了什么payload，观察到什么响应"},
                        },
                        "required": ["finding_id", "note"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "switch_phase",
                    "description": "切换到下一个工作阶段。阶段顺序：task_parsing → info_collection → "
                                   "analysis → verification → reporting。当前阶段完成后再切换。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "phase": {"type": "string", "enum": ["task_parsing", "info_collection", "analysis", "verification", "reporting"]},
                        },
                        "required": ["phase"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_source",
                    "description": "读取本地源码文件内容（用于代码审计）。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "文件路径"},
                            "max_lines": {"type": "integer", "description": "最多读取行数，默认200"},
                        },
                        "required": ["path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "session_status",
                    "description": "查看当前会话状态：阶段、轮次、已发现的漏洞、已确认的事实。",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
        ]

    # --- 工具实现 ---

    def execute(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Execute a tool call and return the result as a string."""
        if tool_name not in self._tools:
            return f"ERROR: Unknown tool '{tool_name}'"

        tool_fn = self._tools[tool_name]
        start = time.time()
        try:
            result = tool_fn(**arguments)
            elapsed = time.time() - start
            logger.debug(f"Tool {tool_name} completed in {elapsed:.1f}s")
            return result
        except Exception as e:
            logger.error(f"Tool {tool_name} failed: {e}")
            return f"ERROR: {tool_name} failed: {str(e)}"

    def http_request(
        self,
        method: str = "GET",
        url: str = "",
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
    ) -> str:
        """
        HTTP request tool — the LLM's primary way to interact with the target.
        Strict timeout discipline: 10s, no retries. Never hangs.
        """
        if not url:
            return "ERROR: url is required"

        # Constraint check
        if hasattr(self, '_constraints') and self._constraints:
            if not self._constraints.check_host(url):
                return f"ERROR: Host out of authorized scope: {url}"

        timeout = self.tool_config.get("http_request", {}).get("default_timeout", 10)

        try:
            if method.upper() == "GET":
                resp = self.http.get(url, params=params or {}, timeout=timeout, no_retry=True)
            elif method.upper() == "POST":
                resp = self.http.post(url, data=params or {}, timeout=timeout, no_retry=True)
            elif method.upper() == "HEAD":
                resp = self.http.head(url, timeout=timeout, no_retry=True)
            else:
                return f"ERROR: Unsupported method {method}"

            if resp.status_code == 0:
                return f"ERROR: Request failed (timeout or connection error): {method} {url}"

            # Format response compactly
            body_preview = resp.body[:3000] if resp.body else "(empty)"
            result = {
                "status": resp.status_code,
                "url": resp.url,
                "elapsed": resp.elapsed_seconds,
                "headers": {k: v for k, v in list(resp.headers.items())[:15]},
                "body_preview": body_preview,
            }
            return json.dumps(result, ensure_ascii=False, indent=2)

        except Exception as e:
            return f"ERROR: HTTP request failed: {str(e)}"

    def python_exec(self, code: str, purpose: str = "") -> str:
        """
        Python execution tool — for data processing, payload construction, etc.
        Audited and logged. Trusted-local mode.
        """
        max_output = self.tool_config.get("python_exec", {}).get("max_output_chars", 8000)

        # Constraint check for destructive actions
        if hasattr(self, '_constraints') and self._constraints:
            if not self._constraints.check_action(code):
                return "ERROR: Code contains blocked destructive operations"

        # Audit record
        audit = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "purpose": purpose,
            "code_preview": code[:500],
            "code_lines": len(code.split("\n")),
        }

        # Capture stdout
        import io
        import contextlib

        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                exec_globals = {"__builtins__": __builtins__}
                exec(code, exec_globals)
            output = stdout.getvalue()
            audit["outcome"] = "success"
        except Exception as e:
            output = f"EXECUTION ERROR: {type(e).__name__}: {str(e)}"
            audit["outcome"] = "error"
            audit["error"] = str(e)

        # Truncate output
        if len(output) > max_output:
            output = output[:max_output] + f"\n... (truncated, {len(output)} chars total)"

        # Save audit
        audit["output_preview"] = output[:200]
        self.python_audit.append(audit)
        self._append_audit(audit)

        self.session.record_step("python_exec", purpose or code[:80])
        return output if output.strip() else "(no output)"

    def rule_scan(self, source_path: str) -> str:
        """Rule engine scan over source files."""
        path = Path(source_path)
        if not path.exists():
            return f"ERROR: Path not found: {source_path}"

        files = []
        code_extensions = {".py", ".php", ".java", ".js", ".ts", ".go", ".rb", ".cs", ".html"}
        skip_dirs = {"node_modules", "vendor", "__pycache__", ".git", "dist", "build"}

        if path.is_file():
            files.append(path)
        else:
            for f in path.rglob("*"):
                if f.suffix.lower() in code_extensions and not any(
                    s in f.parts for s in skip_dirs
                ):
                    files.append(f)

        all_matches = []
        for file_path in files[:20]:  # Limit to 20 files
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                language = self._detect_language(str(file_path))
                matches = self.rule_engine.scan_code(content, str(file_path), language)
                for m in matches:
                    all_matches.append({
                        "vuln_type": m.vuln_type,
                        "confidence": m.confidence,
                        "file": str(file_path),
                        "line": m.line_number,
                        "rule": m.rule_name,
                        "matched": m.matched_text[:120],
                        "sink": m.sink,
                        "source": m.source,
                    })
            except Exception as e:
                logger.debug(f"Rule scan failed for {file_path}: {e}")

        if not all_matches:
            return f"Scanned {len(files)} files: no rule matches found."

        # Sort by confidence
        all_matches.sort(key=lambda x: x["confidence"], reverse=True)

        result = f"Scanned {len(files)} files, {len(all_matches)} matches:\n"
        for m in all_matches[:30]:
            result += (f"  [{m['vuln_type']}] conf={m['confidence']:.2f} "
                       f"{m['file']}:{m['line']} — {m['rule']}\n")
        return result

    def add_finding(self, title: str, severity: str, vuln_type: str,
                    location: str, evidence: str, description: str = "",
                    poc: str = "") -> str:
        """Record a vulnerability finding."""
        finding_id = self.session.add_finding({
            "title": title,
            "severity": severity,
            "vuln_type": vuln_type,
            "description": description,
            "location": location,
            "evidence": evidence,
            "poc_script": poc or None,
        })
        self.session.record_step("add_finding", f"{finding_id}: {title}")
        return f"Finding recorded: {finding_id}"

    def mark_verified(self, finding_id: str, note: str) -> str:
        """Mark a finding as verified."""
        found = False
        for f in self.session.findings:
            if f.get("finding_id") == finding_id:
                found = True
                break
        if not found:
            return f"ERROR: Finding '{finding_id}' not found"
        self.session.mark_verified(finding_id, note)
        self.session.add_confirmed_fact(f"{finding_id}: {note}")
        return f"Finding {finding_id} marked as verified (L2 evidence)"

    def switch_phase(self, phase: str) -> str:
        """Switch to a new phase."""
        self.session.switch_phase(phase)
        return f"Switched to phase: {phase}"

    def read_source(self, path: str, max_lines: int = 200) -> str:
        """Read a source file (for code audit)."""
        file_path = Path(path)
        if not file_path.exists():
            return f"ERROR: File not found: {path}"
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")
            if len(lines) > max_lines:
                preview = "\n".join(lines[:max_lines])
                return f"File: {path} ({len(lines)} lines, showing first {max_lines}):\n{preview}"
            return f"File: {path} ({len(lines)} lines):\n{content}"
        except Exception as e:
            return f"ERROR: Failed to read {path}: {e}"

    def session_status(self) -> str:
        """Current session state."""
        summary = self.session.get_summary()
        status = {
            "phase": self.session.phase,
            "round": self.session.round,
            "target": self.session.target,
            "findings_count": summary["total_findings"],
            "verified_count": summary["verified"],
            "confirmed_facts": self.session.confirmed_facts[-5:],
            "notes": self.session.notes[-5:],
        }
        return json.dumps(status, ensure_ascii=False, indent=2)

    # --- 辅助 ---

    def _detect_language(self, file_path: str) -> str:
        ext = Path(file_path).suffix.lower()
        return {
            ".py": "python", ".php": "php", ".java": "java", ".js": "javascript",
            ".ts": "javascript", ".go": "go", ".rb": "ruby", ".cs": "csharp",
            ".html": "html",
        }.get(ext, "unknown")

    def _append_audit(self, audit: Dict) -> None:
        """Append python exec audit to JSONL file."""
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(audit, ensure_ascii=False) + "\n")
        except Exception:
            pass
