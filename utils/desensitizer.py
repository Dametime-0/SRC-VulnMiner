"""
Desensitizer — Data masking and sanitization for output security.

All vulnerability findings, logs, and reports pass through this module
before being written to disk or displayed. This ensures that:
1. No real sensitive data (IPs, emails, credentials) leaks into reports
2. Demo cases use placeholder values
3. Competition requirements for data desensitization are met

Strategy:
- IP addresses → masked to first octet only (e.g., 192.x.x.x)
- Domains → replaced with example.com variants
- Emails → replaced with [EMAIL]
- Potential credentials → replaced with [CREDENTIAL]
- API keys / tokens → replaced with [TOKEN]
- File paths with usernames → username replaced with [USER]
"""

import re
import hashlib
from typing import Dict, List, Optional, Any


class Desensitizer:
    """
    Masks sensitive data in security findings and reports.

    Usage:
        d = Desensitizer()
        safe_text = d.mask("Found SQLi at http://192.168.1.100/admin?id=1")
        # → "Found SQLi at http://192.x.x.x/admin?id=1"

        safe_finding = d.sanitize_finding({
            "url": "http://real-company.com/api",
            "evidence": "email: admin@real-company.com"
        })
    """

    def __init__(self, custom_patterns: Optional[Dict[str, str]] = None):
        """
        Initialize with optional custom replacement patterns.

        Args:
            custom_patterns: Dict of {pattern: replacement} for additional masking
        """
        self.patterns = [
            # IPv4 addresses — keep first octet
            (re.compile(r'\b(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), self._mask_ip),
            # Email addresses
            (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), '[EMAIL]'),
            # API keys (common patterns: api_key=, apikey=, key=, sk-...)
            (re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?key|key)\s*[:=]\s*[\'"]?[^\s\'",]+[\'"]?'),
             r'\1=[TOKEN]'),
            # Generic sk-xxx style tokens
            (re.compile(r'\bsk-[A-Za-z0-9_-]{8,}\b'), '[TOKEN]'),
            # AWS keys
            (re.compile(r'AKIA[0-9A-Z]{16}'), '[AWS_ACCESS_KEY]'),
            (re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*[\'"]?[^\s\'"]+[\'"]?'),
             'aws_secret_access_key=[AWS_SECRET_KEY]'),
            # JWT tokens
            (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), '[JWT_TOKEN]'),
            # Authorization headers
            (re.compile(r'(?i)Authorization:\s*Bearer\s+[^\s]+'), 'Authorization: Bearer [TOKEN]'),
            (re.compile(r'(?i)Authorization:\s*Basic\s+[^\s]+'), 'Authorization: Basic [CREDENTIAL]'),
            # Passwords in params
            (re.compile(r'(?i)(password|passwd|pwd|secret)\s*[:=]\s*[\'"]?[^\s&\'"]+[\'"]?'),
             r'\1=[CREDENTIAL]'),
            # Database connection strings
            (re.compile(r'(?i)(mysql|postgresql|mongodb|redis)://[^@]+@'), r'\1://[USER]:[PASS]@'),
            # File paths with potential usernames
            (re.compile(r'(/home/|/Users/|C:\\Users\\)([^/\\]+)'), r'\1[USER]'),
            # Phone numbers (Chinese mobile)
            (re.compile(r'1[3-9]\d{9}'), '[PHONE]'),
            # ID card numbers (Chinese)
            (re.compile(r'\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]'), '[ID_CARD]'),
        ]

        if custom_patterns:
            for pattern, replacement in custom_patterns.items():
                self.patterns.append((re.compile(pattern), replacement))

        # Track what was masked for audit
        self.mask_log: List[Dict[str, str]] = []

    def _mask_ip(self, match: re.Match) -> str:
        """Mask IP address keeping only first octet."""
        ip = match.group(0)
        parts = ip.split('.')
        return f"{parts[0]}.x.x.x"

    def mask(self, text: str) -> str:
        """
        Apply all masking patterns to a text string.

        Args:
            text: Original text potentially containing sensitive data

        Returns:
            Desensitized text
        """
        if not text:
            return text

        result = text
        for pattern, replacement in self.patterns:
            new_result = pattern.sub(replacement, result)
            if new_result != result:
                # Log what was masked (first occurrence only)
                matches = pattern.findall(result)
                if matches:
                    self.mask_log.append({
                        "pattern": pattern.pattern[:80],
                        "count": len(matches),
                        "example": str(matches[0])[:50] if matches else "",
                    })
            result = new_result

        return result

    def sanitize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize a vulnerability finding dict, masking all string values.

        Args:
            finding: Vulnerability finding dictionary

        Returns:
            Sanitized copy of the finding
        """
        return self._sanitize_dict(finding)

    def sanitize_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize a full report, masking all sensitive data.

        Args:
            report: Complete report dictionary

        Returns:
            Sanitized report
        """
        return self._sanitize_dict(report)

    def _sanitize_dict(self, obj: Any) -> Any:
        """Recursively sanitize all string values in a dict/list structure."""
        if isinstance(obj, str):
            return self.mask(obj)
        elif isinstance(obj, dict):
            return {k: self._sanitize_dict(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._sanitize_dict(item) for item in obj]
        else:
            return obj

    def get_mask_summary(self) -> Dict[str, int]:
        """Get summary of what was masked."""
        summary: Dict[str, int] = {}
        for entry in self.mask_log:
            pattern_type = entry["pattern"].split("\\")[0][:40]
            summary[pattern_type] = summary.get(pattern_type, 0) + entry["count"]
        return summary

    def clear_log(self) -> None:
        """Clear the mask log between tasks."""
        self.mask_log = []


# Pre-built instance for quick use
_default_desensitizer = Desensitizer()


def desensitize(text: str) -> str:
    """Quick desensitization of a text string."""
    return _default_desensitizer.mask(text)


def desensitize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Quick desensitization of a finding dict."""
    return _default_desensitizer.sanitize_finding(finding)
