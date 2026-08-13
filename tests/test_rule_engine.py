"""
Tests for the Rule Engine — the core of the fast-path analysis.

Verifies that the rule engine correctly:
1. Detects SQL injection patterns in code
2. Detects XSS patterns in code
3. Detects command injection patterns
4. Identifies dangerous functions (sinks)
5. Identifies user input sources
6. Does NOT flag safe code (low false positive rate)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.rule_engine import RuleEngine


def test_sqli_detection_in_code():
    """Rule engine should detect SQL injection in concatenated queries."""
    engine = RuleEngine(rules_dir=str(Path(__file__).parent.parent / "rules"))
    engine.load_all_rules()

    # Vulnerable code: string concatenation in SQL query
    vulnerable_code = '''
import sqlite3

def get_user(username):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def search_products(keyword):
    cursor = db.cursor()
    # VULNERABLE: f-string in SQL
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{keyword}%'")
    return cursor.fetchall()
'''
    matches = engine.scan_code(vulnerable_code, "app.py", "python")

    sqli_matches = [m for m in matches if m.vuln_type == "sql_injection"]
    assert len(sqli_matches) > 0, f"Expected SQLi matches, got {len(sqli_matches)}"
    print(f"  ✓ SQLi detection: {len(sqli_matches)} matches found")


def test_safe_code_not_flagged():
    """Rule engine should NOT flag properly parameterized queries."""
    engine = RuleEngine(rules_dir=str(Path(__file__).parent.parent / "rules"))
    engine.load_all_rules()

    safe_code = '''
import sqlite3

def get_user_safe(username):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    # SAFE: Parameterized query
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()

def add_product_safe(name, price):
    cursor.execute(
        "INSERT INTO products (name, price) VALUES (?, ?)",
        (name, price)
    )
'''
    matches = engine.scan_code(safe_code, "safe_app.py", "python")

    # Should have few or no high-confidence SQLi matches
    high_conf_sqli = [
        m for m in matches
        if m.vuln_type == "sql_injection" and m.confidence > 0.6
    ]
    assert len(high_conf_sqli) == 0, \
        f"Safe code should not have high-confidence SQLi matches, got {len(high_conf_sqli)}"
    print(f"  ✓ Safe code check: {len(high_conf_sqli)} false positives (expected 0)")


def test_dangerous_function_detection():
    """Rule engine should detect dangerous functions even without explicit YAML rules."""
    engine = RuleEngine()
    engine.load_all_rules()

    code_with_dangerous_calls = '''
import os
import subprocess
import pickle

def admin_tools(cmd):
    # VULNERABLE: OS command execution
    os.system(cmd)
    result = subprocess.run(cmd, shell=True)

def load_config(data):
    # VULNERABLE: Unsafe deserialization
    return pickle.loads(data)

def proxy_fetch(url):
    # VULNERABLE: SSRF
    import requests
    return requests.get(url)
'''
    matches = engine.scan_code(code_with_dangerous_calls, "admin.py", "python")

    # Check for command injection
    cmd_matches = [m for m in matches if m.vuln_type == "command_injection"]
    assert len(cmd_matches) > 0, "Should detect os.system with potential command injection"

    # Check for SSRF
    ssrf_matches = [m for m in matches if m.vuln_type == "ssrf"]
    assert len(ssrf_matches) > 0, "Should detect requests.get with potential SSRF"

    print(f"  ✓ Dangerous functions: {len(matches)} matches "
          f"(CMD: {len(cmd_matches)}, SSRF: {len(ssrf_matches)})")


def test_xss_detection():
    """Rule engine should detect XSS-prone patterns."""
    engine = RuleEngine(rules_dir=str(Path(__file__).parent.parent / "rules"))
    engine.load_all_rules()

    vulnerable_js = '''
function displaySearch(query) {
    // VULNERABLE: innerHTML with user input
    document.getElementById("results").innerHTML = query;
}

function loadProfile(data) {
    // VULNERABLE: document.write
    document.write("<h1>" + data.name + "</h1>");
}
'''
    matches = engine.scan_code(vulnerable_js, "app.js", "javascript")

    xss_matches = [m for m in matches if m.vuln_type == "xss"]
    assert len(xss_matches) > 0, f"Expected XSS matches, got {len(xss_matches)}"
    print(f"  ✓ XSS detection: {len(xss_matches)} matches")


def test_http_response_scanning():
    """Rule engine should detect SQL errors in HTTP responses."""
    engine = RuleEngine(rules_dir=str(Path(__file__).parent.parent / "rules"))
    engine.load_all_rules()

    # Simulated SQL error response
    error_response = """
    <html><body>
    <h1>Database Error</h1>
    <p>You have an error in your SQL syntax; check the manual that corresponds
    to your MySQL server version for the right syntax to use near
    '' OR '1'='1' --' at line 1</p>
    </body></html>
    """

    matches = engine.scan_response(
        url="http://demo.local/login",
        response_body=error_response,
        request_payload="' OR '1'='1",
    )

    sqli_matches = [m for m in matches if m.vuln_type == "sql_injection"]
    assert len(sqli_matches) > 0, "Should detect SQL error in response"
    print(f"  ✓ HTTP response scan: {len(sqli_matches)} SQL error(s) detected")


def test_param_scanning():
    """Rule engine should flag sensitive parameter names."""
    engine = RuleEngine(rules_dir=str(Path(__file__).parent.parent / "rules"))
    engine.load_all_rules()

    params = ["id", "file", "url", "cmd", "search"]
    matches = engine.scan_params("http://demo.local/api", params)

    assert len(matches) > 0, "Should flag sensitive parameters"
    # Should flag 'file' for path traversal
    traversal = [m for m in matches if m.vuln_type == "path_traversal"]
    assert len(traversal) > 0, "Should flag 'file' parameter for path traversal"

    print(f"  ✓ Parameter scan: {len(matches)} sensitive params found")


def test_fingerprint_dedup():
    """Fingerprint generation should be consistent for same input."""
    engine = RuleEngine()
    fp1 = engine.fingerprint("sqli", "app.py:42", "username")
    fp2 = engine.fingerprint("sqli", "app.py:42", "username")
    fp3 = engine.fingerprint("sqli", "app.py:43", "username")

    assert fp1 == fp2, "Same input should produce same fingerprint"
    assert fp1 != fp3, "Different location should produce different fingerprint"
    print(f"  ✓ Fingerprint: consistent dedup keys (fp1={fp1})")


def run_all_tests():
    """Run all rule engine tests."""
    print("\n[Rule Engine Tests]")
    print("-" * 40)

    tests = [
        test_sqli_detection_in_code,
        test_safe_code_not_flagged,
        test_dangerous_function_detection,
        test_xss_detection,
        test_http_response_scanning,
        test_param_scanning,
        test_fingerprint_dedup,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {test.__name__} — {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {test.__name__} — {e}")
            failed += 1

    print("-" * 40)
    print(f"  Results: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
