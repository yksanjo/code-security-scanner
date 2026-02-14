# 🔒 Code Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/Python-3.11+-blue" alt="Python">
  <img src="https://img.shields.io/badge/AI-Powered-purple" alt="AI">
</p>

> AI-powered code security scanner - detect vulnerabilities, secrets, and security issues in your codebase

A comprehensive security scanning tool that uses AI to detect vulnerabilities, hardcoded secrets, credentials, and other security issues in your codebase. Built with Python and integrated with LLM APIs for intelligent analysis.

## ✨ Features

- **Secret Detection** - Find API keys, tokens, passwords, and private keys
- **Vulnerability Scanning** - Detect common security vulnerabilities (OWASP Top 10)
- **AI-Powered Analysis** - Use LLM to understand context and reduce false positives
- **Multiple Language Support** - JavaScript, TypeScript, Python, Go, Rust, Java, and more
- **CI/CD Integration** - GitHub Actions, GitLab CI, Jenkins
- **Custom Rules** - Define your own detection patterns
- **Detailed Reports** - JSON, SARIF, and HTML output formats
- **Remediation Suggestions** - Get AI-generated fix recommendations

## 🛠️ Tech Stack

- **Language**: Python 3.11+
- **AI**: OpenAI API, Anthropic Claude API
- **Code Analysis**: AST parsing, regex patterns
- **Testing**: pytest, coverage
- **Deployment**: PyPI, npm

## 🚀 Quick Start

### Installation

```bash
# From PyPI
pip install code-security-scanner

# Or from source
git clone https://github.com/yksanjo/code-security-scanner.git
cd code-security-scanner
pip install -e .
```

### Basic Usage

```bash
# Scan a directory
code-scan ./src

# Scan with AI analysis
code-scan ./src --ai-analysis

# Output to file
code-scan ./src --format json --output report.json

# Scan with custom rules
code-scan ./src --rules custom_rules.yaml
```

### Python API

```python
from code_security_scanner import Scanner

scanner = Scanner()
results = scanner.scan_directory("./src")

for issue in results.issues:
    print(f"{issue.severity}: {issue.message}")
```

## 📊 Supported Detections

### Secrets & Credentials
- AWS Keys
- GitHub Tokens
- API Keys (generic)
- Private Keys (RSA, DSA, EC)
- Database Connection Strings
- Environment Variables with secrets

### Vulnerabilities
- SQL Injection patterns
- XSS vulnerabilities
- Command Injection
- Path Traversal
- Insecure Random
- Hardcoded Passwords

### Best Practices
- Missing error handling
- Unverified SSL/TLS
- Insecure dependencies
- Debug mode enabled
- TODO: security comments

## 🔌 Integrations

### GitHub Actions

```yaml
- name: Security Scan
  uses: yksanjo/code-security-scanner-action@v1
  with:
    directory: ./src
    ai-analysis: true
```

### GitLab CI

```yaml
security-scan:
  script:
    - code-scan ./src --format sarif > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## 📁 Project Structure

```
code-security-scanner/
├── src/
│   └── code_security_scanner/
│       ├── scanners/        # Detection engines
│       ├── ai/             # LLM integration
│       ├── formatters/     # Output formatters
│       └── cli.py          # Command line interface
├── tests/                  # Test suite
├── docs/                   # Documentation
└── pyproject.toml         # Package configuration
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md).

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 👤 Author

Built by [Yoshikondo](https://github.com/yksanjo)

---

<div align="center">

⭐ Star us on GitHub | 🔔 Subscribe to updates | 💼 [LinkedIn](https://linkedin.com/in/yksanjo)

</div>
