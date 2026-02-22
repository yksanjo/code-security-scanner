"""Main scanner module for code security scanning."""

import os
import re
import time
from pathlib import Path
from typing import List, Optional

from .models import (
    ScanResult,
    SecurityIssue,
    Severity,
    IssueType,
)


# Common secret patterns
SECRET_PATTERNS = {
    "aws_access_key": {
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "severity": Severity.CRITICAL,
        "message": "AWS Access Key detected",
        "remediation": "Use environment variables or AWS Secrets Manager instead of hardcoding credentials.",
    },
    "github_token": {
        "pattern": r"(?:gh[pousr]_[A-Za-z0-9]{20,255})",
        "severity": Severity.CRITICAL,
        "message": "GitHub Token detected",
        "remediation": "Revoke this token immediately and use GitHub Apps or OAuth instead.",
    },
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "message": "Private Key detected",
        "remediation": "Store private keys in a secure secrets manager, never commit to version control.",
    },
    "api_key": {
        "pattern": r"(?:api[_-]?key|apikey|api_secret|apisecret)[\s=:>\"']+[a-zA-Z0-9]{20,}",
        "severity": Severity.HIGH,
        "message": "Potential API Key detected",
        "remediation": "Use environment variables to store API keys.",
    },
    "password": {
        "pattern": r"(?:password|passwd|pwd)[\s=:>\"']+[^\s\"']+",
        "severity": Severity.HIGH,
        "message": "Hardcoded password detected",
        "remediation": "Use a secrets manager or environment variables.",
    },
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        "severity": Severity.HIGH,
        "message": "JWT Token detected",
        "remediation": "Ensure JWTs are not exposed in source code or logs.",
    },
    "database_url": {
        "pattern": r"(?:mongodb(?:\+srv)?|mysql|postgresql|postgres)://[^\s\"']+",
        "severity": Severity.HIGH,
        "message": "Database connection string detected",
        "remediation": "Use environment variables for database credentials.",
    },
}


# Vulnerability patterns
VULNERABILITY_PATTERNS = {
    "sql_injection": {
        "pattern": r"(?:execute|exec|query|cursor\.execute)\s*\(\s*[\"'](?:SELECT|INSERT|UPDATE|DELETE).*?%s",
        "severity": Severity.CRITICAL,
        "message": "Potential SQL Injection vulnerability",
        "remediation": "Use parameterized queries instead of string concatenation.",
    },
    "hardcoded_sql": {
        "pattern": r"(?:execute|exec|query)\s*\(\s*[\"'].*(?:SELECT|INSERT|UPDATE|DELETE).*?[\"']",
        "severity": Severity.MEDIUM,
        "message": "Hardcoded SQL query detected",
        "remediation": "Use an ORM or parameterized queries.",
    },
    "eval_usage": {
        "pattern": r"\beval\s*\(",
        "severity": Severity.HIGH,
        "message": "Use of eval() detected",
        "remediation": "Avoid using eval() as it can execute arbitrary code.",
    },
    "os_command": {
        "pattern": r"(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(",
        "severity": Severity.HIGH,
        "message": "Potential OS Command Injection",
        "remediation": "Validate and sanitize all user input before passing to shell commands.",
    },
    "insecure_random": {
        "pattern": r"random\.(?:random|choice|shuffle)\s*\(",
        "severity": Severity.MEDIUM,
        "message": "Insecure random usage detected",
        "remediation": "Use secrets.token_* for cryptographic randomness.",
    },
    "hardcoded_ip": {
        "pattern": r"(?:http|https)://(?:\d{1,3}\.){3}\d{1,3}",
        "severity": Severity.LOW,
        "message": "Hardcoded IP address detected",
        "remediation": "Use environment variables for configuration.",
    },
}


class Scanner:
    """Main scanner class for detecting security issues."""

    def __init__(self, extensions: Optional[List[str]] = None):
        """Initialize the scanner.
        
        Args:
            extensions: List of file extensions to scan. Defaults to common code files.
        """
        self.extensions = extensions or [
            ".py", ".js", ".ts", ".jsx", ".tsx",
            ".java", ".go", ".rb", ".php", ".cs",
            ".sh", ".yaml", ".yml", ".json", ".xml",
        ]
        self.exclude_dirs = {
            "node_modules", ".git", "__pycache__",
            "venv", ".venv", "dist", "build",
            ".next", ".nuxt", "coverage", ".tox",
        }

    def scan_directory(self, directory: str) -> ScanResult:
        """Scan a directory for security issues.
        
        Args:
            directory: Path to directory to scan.
            
        Returns:
            ScanResult with all found issues.
        """
        start_time = time.time()
        result = ScanResult()
        
        dir_path = Path(directory)
        if not dir_path.exists():
            return result
            
        for file_path in self._get_files(dir_path):
            issues = self._scan_file(file_path)
            result.issues.extend(issues)
            result.files_scanned += 1
            
        result.scan_duration_seconds = time.time() - start_time
        return result

    def _get_files(self, directory: Path) -> List[Path]:
        """Get all files to scan in directory."""
        files = []
        for item in directory.rglob("*"):
            if item.is_file():
                # Check if we should scan this file
                if item.suffix in self.extensions:
                    # Check if in excluded directory
                    if not any(excl in item.parts for excl in self.exclude_dirs):
                        files.append(item)
        return files

    def _scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan a single file for security issues."""
        issues = []
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return issues
            
        content = "".join(lines)
        
        # Check each line for issues
        for line_num, line in enumerate(lines, start=1):
            # Check secret patterns
            for rule_id, rule in SECRET_PATTERNS.items():
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    issues.append(SecurityIssue(
                        severity=rule["severity"],
                        issue_type=IssueType.SECRET,
                        message=rule["message"],
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        remediation=rule["remediation"],
                        rule_id=rule_id,
                    ))
                    
            # Check vulnerability patterns
            for rule_id, rule in VULNERABILITY_PATTERNS.items():
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    issues.append(SecurityIssue(
                        severity=rule["severity"],
                        issue_type=IssueType.VULNERABILITY,
                        message=rule["message"],
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        remediation=rule["remediation"],
                        rule_id=rule_id,
                    ))
                    
        return issues
