"""Tests for code security scanner."""

import tempfile
from pathlib import Path

import pytest

from code_security_scanner import Scanner
from code_security_scanner.models import Severity, IssueType


class TestScanner:
    """Test cases for the Scanner class."""

    def test_scanner_initialization(self):
        """Test scanner can be initialized."""
        scanner = Scanner()
        assert scanner is not None
        assert scanner.extensions is not None

    def test_scan_directory_nonexistent(self):
        """Test scanning a nonexistent directory."""
        scanner = Scanner()
        result = scanner.scan_directory("/nonexistent/path")
        assert result.files_scanned == 0
        assert len(result.issues) == 0

    def test_detect_aws_key(self):
        """Test detection of AWS access keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file with AWS key
            test_file = Path(tmpdir) / "config.py"
            test_file.write_text('AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"')
            
            scanner = Scanner()
            result = scanner.scan_directory(tmpdir)
            
            assert result.files_scanned == 1
            assert len(result.issues) > 0
            
            # Check for AWS key issue
            aws_issues = [i for i in result.issues if "aws" in i.message.lower()]
            assert len(aws_issues) > 0
            assert aws_issues[0].severity == Severity.CRITICAL

    def test_detect_github_token(self):
        """Test detection of GitHub tokens."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "config.py"
            test_file.write_text('GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"')
            
            scanner = Scanner()
            result = scanner.scan_directory(tmpdir)
            
            github_issues = [i for i in result.issues if "github" in i.message.lower()]
            assert len(github_issues) > 0

    def test_detect_password(self):
        """Test detection of hardcoded passwords."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "config.py"
            test_file.write_text('password = "mysecretpassword123"')
            
            scanner = Scanner()
            result = scanner.scan_directory(tmpdir)
            
            password_issues = [i for i in result.issues if "password" in i.message.lower()]
            assert len(password_issues) > 0
            assert password_issues[0].severity == Severity.HIGH

    def test_detect_sql_injection(self):
        """Test detection of SQL injection patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "query.py"
            test_file.write_text('cursor.execute("SELECT * FROM users WHERE id=" + user_id)')
            
            scanner = Scanner()
            result = scanner.scan_directory(tmpdir)
            
            sql_issues = [i for i in result.issues if "sql" in i.message.lower()]
            assert len(sql_issues) > 0

    def test_exclude_node_modules(self):
        """Test that node_modules is excluded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file inside node_modules
            node_modules = Path(tmpdir) / "node_modules" / "package"
            node_modules.parent.mkdir(parents=True)
            node_modules.write_text('password = "secret"')
            
            scanner = Scanner()
            result = scanner.scan_directory(tmpdir)
            
            # Should not find the password in node_modules
            assert len(result.issues) == 0

    def test_multiple_files(self):
        """Test scanning multiple files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple files
            for i in range(3):
                test_file = Path(tmpdir) / f"file{i}.py"
                test_file.write_text(f'api_key = "key{i}"')
            
            scanner = Scanner()
            result = scanner.scan_directory(tmpdir)
            
            assert result.files_scanned == 3
