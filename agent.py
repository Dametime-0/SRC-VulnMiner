#!/usr/bin/env python3
"""
SRC Vulnerability Mining Agent v2 — LLM驱动的漏洞挖掘Agent
LLM主导 + 工具层 + 会话持久化

███████╗██████╗  ██████╗    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
██╔════╝██╔══██╗██╔════╝    ██║   ██║██║   ██║██║     ████╗  ██║
███████╗██████╔╝██║         ██║   ██║██║   ██║██║     ██╔██╗ ██║
╚════██║██╔══██╗██║         ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
███████║██║  ██║╚██████╗     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
╚══════╝╚═╝  ╚═╝ ╚═════╝      ╚═══╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝

用法：
    python agent.py --task task.json
    python agent.py --text "扫描 http://target 的SQL注入"
    echo '{"target":"..."}' | python agent.py --stdin
"""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from utils.logger import get_logger
from utils.llm_client import LLMClient
from utils.http_client import HTTPClient
from utils.rule_engine import RuleEngine
from core.orchestrator import AgentOrchestrator

logger = get_logger("agent.main")


def load_config(config_path: str = "config.yaml") -> dict:
    """Load YAML config + .env file (API key不写死在config里)."""
    import os
    import yaml

    # Load .env file into environment
    env_file = Path(".env")
    if env_file.exists():
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key.strip(), value.strip())

    config_file = Path(config_path)
    if not config_file.exists():
        logger.error(f"Config not found: {config_path}")
        sys.exit(1)
    with open(config_file, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class SRCVulnMiner:
    """v2: LLM驱动的漏洞挖掘Agent。"""

    def __init__(self, config_path: str = "config.yaml"):
        self.config = load_config(config_path)

        # 核心组件
        self.llm_client = LLMClient(self.config.get("llm", {}))
        self.http_client = HTTPClient(self.config.get("http", {}))
        self.rule_engine = RuleEngine(
            self.config.get("tools", {}).get("rule_scan", {}).get("rules_dir", "rules/")
        )
        rule_count = self.rule_engine.load_all_rules()

        self.orchestrator = AgentOrchestrator(
            self.llm_client, self.http_client, self.rule_engine, self.config
        )

        logger.info(f"SRC-VulnMiner v2 initialized. Rules: {rule_count}, "
                    f"Model: {self.config.get('llm', {}).get('model')}")

    def run(self, task_input: dict) -> dict:
        """Run the agent on a task."""
        return self.orchestrator.run(task_input)

    def run_from_json(self, json_input: str) -> str:
        """Range-compatible JSON input/output."""
        try:
            task = json.loads(json_input)
        except json.JSONDecodeError as e:
            return json.dumps({"status": "error", "error": f"Invalid JSON: {e}"})
        report = self.run(task)
        return json.dumps(report, ensure_ascii=False, indent=2)

    def run_from_text(self, task_text: str) -> dict:
        """Natural language task input."""
        return self.run({"task_text": task_text})


def main():
    parser = argparse.ArgumentParser(
        description="SRC Vulnerability Mining Agent v2 — LLM驱动",
        epilog="""
Examples:
  python agent.py --task task.json
  python agent.py --text "扫描 http://testphp.vulnweb.com 的SQL注入和XSS"
  echo '{"target":"http://127.0.0.1:5000","vuln_types":["sqli"]}' | python agent.py --stdin
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--task", "-t", help="JSON任务文件路径")
    group.add_argument("--text", "-x", help="自然语言任务描述")
    group.add_argument("--stdin", "-s", action="store_true", help="从stdin读JSON")
    parser.add_argument("--config", "-c", default="config.yaml")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    # 任务输入
    if args.task:
        with open(args.task, "r", encoding="utf-8") as f:
            task_input = json.load(f)
    elif args.text:
        task_input = {"task_text": args.text}
    else:
        task_input = json.loads(sys.stdin.read())

    # 运行
    agent = SRCVulnMiner(config_path=args.config)
    report = agent.run(task_input)

    # 输出
    print(json.dumps(report, ensure_ascii=False, indent=2))

    # 退出码：0=OK, 2=有未验证发现, 3=错误
    if report.get("status") == "error":
        sys.exit(3)
    elif report.get("summary", {}).get("uncertain", 0) > 0 and \
         report.get("summary", {}).get("verified_vulns", 0) == 0:
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
