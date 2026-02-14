"""Data models for code security scanner."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
from datetime import datetime


class Severity(Enum):
    """Severity levels for security issues."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IssueType(Enum):
    """Types of security issues."""
    SECRET = "secret"
    VULNERABILITY = "vulnerability"
    BEST_PRACTICE = "best_practice"
    CREDENTIALS = "credentials"


@dataclass
class SecurityIssue:
    """Represents a security issue found in code."""
    severity: Severity
    issue_type: IssueType
    message: str
    file_path: str
    line_number: int
    column_start: int = 0
    column_end: int = 0
    code_snippet: str = ""
    remediation: str = ""
    rule_id: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "severity": self.severity.value,
            "type": self.issue_type.value,
            "message": self.message,
            "file": self.file_path,
            "line": self.line_number,
            "column_start": self.column_start,
            "column_end": self.column_end,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "rule_id": self.rule_id,
        }


@dataclass
class ScanResult:
    """Results from a security scan."""
    issues: List[SecurityIssue] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    scan_duration_seconds: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    scanner_version: str = "1.0.0"

    @property
    def critical_count(self) -> int:
        """Get count of critical issues."""
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Get count of high severity issues."""
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Get count of medium severity issues."""
        return sum(1 for i in self.issues if i.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Get count of low severity issues."""
        return sum(1 for i in self.issues if i.severity == Severity.LOW)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "issues": [i.to_dict() for i in self.issues],
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": len(self.issues),
            },
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "scan_duration_seconds": self.scan_duration_seconds,
            "timestamp": self.timestamp.isoformat(),
            "scanner_version": self.scanner_version,
        }
