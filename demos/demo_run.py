#!/usr/bin/env python3
"""
Demo Run Script v2
===================
LLM驱动模式：启动演示靶场 + 运行Agent

用法:
    # 需要 LLM_API_KEY 环境变量（或在config.yaml中配置）
    python demos/demo_run.py --auto
"""

import sys
import time
import subprocess
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent import SRCVulnMiner


def main():
    parser = argparse.ArgumentParser(description="Demo: LLM驱动的漏洞挖掘Agent")
    parser.add_argument("--auto", action="store_true", help="自动启动演示靶场")
    parser.add_argument("--target", default="http://127.0.0.1:5000")
    parser.add_argument("--rounds", type=int, default=25, help="LLM最大轮次")
    args = parser.parse_args()

    target_process = None
    if args.auto:
        print("[*] 启动演示靶场...")
        demo_app = Path(__file__).parent / "demo_target" / "app.py"
        target_process = subprocess.Popen(
            [sys.executable, str(demo_app)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        print("[*] 靶场已启动")

    try:
        agent = SRCVulnMiner()
        # 覆盖轮次上限
        agent.orchestrator.max_rounds = args.rounds

        task = {
            "task_id": "demo_001",
            "target": args.target,
            "source_path": str(Path(__file__).parent / "demo_target"),
            "vuln_types": [
                "sql_injection", "xss", "idor", "ssrf",
                "path_traversal", "command_injection",
            ],
            "constraints": {"destructive_allowed": False},
            "task_text": (
                f"扫描 {args.target} 的常见Web漏洞（SQL注入/XSS/IDOR/SSRF/路径遍历/命令注入）。"
                "源码位于source_path。所有测试必须非破坏性。"
            ),
        }

        print(f"\n[*] 目标: {args.target}")
        print(f"[*] 漏洞类型: {len(task['vuln_types'])} 种")
        print("[*] 开始LLM驱动的漏洞挖掘...\n")

        report = agent.run(task)
        print(f"\n[*] 完成。报告已保存到 output/")

    finally:
        if target_process:
            target_process.terminate()
            target_process.wait()
            print("[*] 靶场已停止")


if __name__ == "__main__":
    main()
