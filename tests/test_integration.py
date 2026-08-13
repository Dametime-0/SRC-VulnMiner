"""
Integration tests for SRC-VulnMiner v2 (LLM-driven architecture).

Tests the core components WITHOUT requiring LLM API access:
1. Session state management
2. Constraint enforcement
3. Tool registry (http_request, rule_scan, add_finding, etc.)
4. Rule engine + analyzer integration
5. Desensitization
6. Report generation from session state
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def make_test_agent():
    """Create an agent instance with mock LLM for testing."""
    from agent import SRCVulnMiner
    agent = SRCVulnMiner()
    # Mock the LLM client so no API calls happen
    from utils.llm_client import LLMClient, LLMResponse

    class MockLLM(LLMClient):
        def __init__(self):
            self.total_cost_usd = 0.0
            self.total_calls = 0
            self.total_tokens = 0
            self._prompt_cache = {}
            self._prompts_dir = Path("prompts")

        def chat(self, messages, system_prompt="", **kwargs):
            self.total_calls += 1
            return LLMResponse(
                content="YES", model="mock", prompt_tokens=10,
                completion_tokens=2, total_tokens=12,
                cost_usd=0.0, latency_seconds=0.001,
            )

        def chat_with_tools(self, messages, system_prompt="", tools=None, **kwargs):
            self.total_calls += 1
            r = LLMResponse(
                content="", model="mock", prompt_tokens=100,
                completion_tokens=20, total_tokens=120,
                cost_usd=0.0, latency_seconds=0.001,
            )
            r.tool_calls = []
            return r

    agent.llm_client = MockLLM()
    agent.orchestrator.llm = MockLLM()
    return agent


def test_session_state():
    """Session should track findings, phases, and rounds correctly."""
    from core.session import AgentSession

    session = AgentSession({"session": {"output_dir": "output", "session_dir": "sessions"}})
    session.init("test_001", "http://demo.local", {"vuln_types": ["sqli"]})

    # Phase management
    assert session.phase == "task_parsing"
    session.switch_phase("info_collection")
    assert session.phase == "info_collection"

    # Findings
    fid = session.add_finding({
        "title": "Test SQLi",
        "severity": "high",
        "vuln_type": "sql_injection",
        "location": "app.py:42",
        "evidence": "SELECT * FROM users WHERE id = ",
    })
    assert fid == "F001"
    assert len(session.findings) == 1

    # Dedup: same vuln_type+location updates instead of adding
    session.add_finding({
        "title": "Test SQLi updated",
        "severity": "high",
        "vuln_type": "sql_injection",
        "location": "app.py:42",
        "evidence": "updated evidence",
    })
    assert len(session.findings) == 1
    assert session.findings[0]["title"] == "Test SQLi updated"

    # Verification
    session.mark_verified("F001", "Verified with payload ' OR '1'='1")
    assert session.findings[0]["verification_status"] == "verified"
    assert session.findings[0]["evidence_level"] == "L2"

    # Summary
    summary = session.get_summary()
    assert summary["total_findings"] == 1
    assert summary["verified"] == 1
    print(f"  [PASS] Session state: {summary}")


def test_constraints():
    """Constraint manager should enforce host and action limits."""
    from core.constraints import ConstraintManager

    cm = ConstraintManager()
    cm.load_from_task({
        "target": "http://demo.local",
        "constraints": {"destructive_allowed": False},
    })

    # In-scope host allowed
    assert cm.check_host("http://demo.local/login")
    assert cm.check_host("http://127.0.0.1:5000/x")

    # Destructive action blocked
    assert not cm.check_action("DROP TABLE users")
    assert not cm.check_action("rm -rf /")

    # Safe action allowed
    assert cm.check_action("SELECT * FROM users WHERE id = '1'")

    # Violations tracked
    summary = cm.get_violation_summary()
    assert summary["total_violations"] >= 2
    print(f"  [PASS] Constraints: {summary['total_violations']} violations detected")


def test_tool_registry():
    """Tool registry should execute tools correctly."""
    from core.session import AgentSession
    from core.tools import ToolRegistry
    from utils.rule_engine import RuleEngine

    session = AgentSession({"session": {"output_dir": "output", "session_dir": "sessions"}})
    session.init("test_002", "http://demo.local", {})

    engine = RuleEngine(rules_dir="rules")
    engine.load_all_rules()

    registry = ToolRegistry(session, None, engine, {"tools": {}})

    # add_finding tool
    result = registry.add_finding(
        title="Test finding",
        severity="high",
        vuln_type="sql_injection",
        location="test.py:10",
        evidence="concat query",
    )
    assert "F001" in result
    assert len(session.findings) == 1

    # mark_verified tool
    result = registry.mark_verified("F001", "payload worked")
    assert "verified" in result

    # mark_verified with bad ID
    result = registry.mark_verified("F999", "nope")
    assert "not found" in result

    # session_status tool
    result = registry.session_status()
    assert "phase" in result

    # switch_phase tool
    registry.switch_phase("analysis")
    assert session.phase == "analysis"

    print("  [PASS] Tool registry: 5 tools exercised")


def test_rule_scan_tool():
    """rule_scan tool should find vulnerabilities in demo app source."""
    from core.session import AgentSession
    from core.tools import ToolRegistry
    from utils.rule_engine import RuleEngine

    session = AgentSession({"session": {"output_dir": "output", "session_dir": "sessions"}})
    session.init("test_003", "http://demo.local", {})

    engine = RuleEngine(rules_dir="rules")
    engine.load_all_rules()

    registry = ToolRegistry(session, None, engine, {"tools": {}})
    result = registry.rule_scan("demos/demo_target/app.py")

    assert "sql_injection" in result, f"Should find SQLi patterns: {result[:200]}"
    print(f"  [PASS] Rule scan: found SQLi in demo source")


def test_desensitization():
    """Desensitizer should mask sensitive data."""
    from utils.desensitizer import Desensitizer

    d = Desensitizer()
    masked = d.mask("Server at 192.168.1.100, contact admin@real.com, key=sk-abc123")
    assert "192.x.x.x" in masked
    assert "[EMAIL]" in masked
    assert "[TOKEN]" in masked
    print("  [PASS] Desensitization: 3 pattern types")


def test_report_generation():
    """Report should be generated from session state with all metrics."""
    from core.session import AgentSession
    import time

    session = AgentSession({"session": {"output_dir": "output", "session_dir": "sessions"}})
    session.init("test_004", "http://demo.local", {"vuln_types": ["sqli"]})
    session.add_finding({
        "title": "SQLi in login",
        "severity": "high",
        "vuln_type": "sql_injection",
        "location": "app.py:132",
        "evidence": "f-string SQL",
    })
    session.mark_verified("F001", "tested with payload")
    session.record_llm_call(1000, 500, 0.005)
    session.record_round_time(2.5)

    summary = session.get_summary()
    assert summary["total_findings"] == 1
    assert summary["verified"] == 1
    assert summary["llm_calls"] == 1
    assert summary["llm_cost_usd"] == 0.005
    print(f"  [PASS] Report metrics: {summary}")


def run_all_tests():
    print("\n[Integration Tests v2]")
    print("-" * 40)

    tests = [
        test_session_state,
        test_constraints,
        test_tool_registry,
        test_rule_scan_tool,
        test_desensitization,
        test_report_generation,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] {test.__name__} — {e}")
            failed += 1
        except Exception as e:
            print(f"  [ERROR] {test.__name__} — {type(e).__name__}: {e}")
            failed += 1

    print("-" * 40)
    print(f"  Results: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
