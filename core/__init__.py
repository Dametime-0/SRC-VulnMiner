"""
Core — LLM驱动的Agent核心。

与旧版固定Pipeline的本质区别：
- 旧版：6个模块按固定顺序执行，LLM只是被调用的分析函数
- 新版：LLM是驾驶员，每轮自主决定调用哪个工具，阶段可以流转

核心组件：
- orchestrator: LLM驱动的轮次循环
- session: 会话状态持久化（findings、steps、notes）
- tools: 工具注册表（http_request / python_exec / rule_scan / add_finding）
- constraints: 任务约束执行
"""

from .orchestrator import AgentOrchestrator
from .session import AgentSession
from .tools import ToolRegistry
from .constraints import ConstraintManager

__all__ = ["AgentOrchestrator", "AgentSession", "ToolRegistry", "ConstraintManager"]
