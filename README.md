# Multi-Modal-Scanner: Standalone Desktop App

> Full PyQt6 desktop application for regulated-environment security assessment. Runs independently — no Claude Code, no Anthropic API dependency. Built and maintained by a senior information security professional with 20 years of GRC and security management experience across financial services, healthcare, and real estate.

---

## What This Does

A standalone GUI application that provides **seven assessment workflows**:

- **Website Vulnerability Assessment** — Evaluates web applications against 67 controls across 13 families
- **AI Agent Assessment** — Evaluates Claude skills, OpenAI GPTs, MCP servers, LangChain/LangGraph apps, Bedrock agents, and other AI agents against the same controls library, identifying risks specific to AI-augmented workflows
- **API Vulnerability Assessment** — Tests APIs against OWASP API Security Top 10 and 53 controls across 17 families, covering authentication, authorization, rate limiting, data exposure, and SSRF
- **Source Code Review** — Static analysis of codebases against 51 controls across 12 families covering security flaws, complexity risks, and development practice gaps
- **STIG Compliance Assessment** — Imports DISA STIG XCCDF files, parses rules into a structured controls library, and produces a compliance checklist report in CAT I/II/III severity format
- **OS & Software Assessment** — Scans Windows and Linux hosts for patch compliance, EOL software, insecure services, and CVE exposure *(this app only — not available in the Claude Code skill)*
- **Connected Systems Assessment** — Correlates findings from two or more completed assessments to detect multi-step attack chains spanning connected systems, with CVSS re-scoring and reachability promotion analysis (27 controls across 9 families)

---

## Key Features

**Persistent scan history** — All assessments are stored in a local SQLite database. Rescan the same target and compare results over time without re-entering context.

**Prior report import** — Import a previous assessment report to carry forward false-positive decisions and reviewer notes into the next scan cycle. Eliminates re-triaging findings that were already evaluated.

**In-app triage interface** — Review findings, confirm or suppress results, and add notes directly in the application before exporting.

**No Anthropic API required** — The scan engine runs locally without calling Claude. Website and API scans require network access to reach their targets; OS, code review, STIG, and agent assessments run without any external network access. Designed for use in environments where a Claude API connection is not available or not permitted.

**Windows and Linux support** — The OS & Software scanner has separate code paths for both platforms.

---

## Requirements

- Python 3.10 or later
- PyQt6 >= 6.6.0
- requests >= 2.31.0
- beautifulsoup4 >= 4.12.0
- pyyaml >= 6.0

---

## Installation

```bash
# Clone the repository
git clone https://github.com/CavenderProjects/Multi-Modal-Scanner_Standalone.git
cd Multi-Modal-Scanner_Standalone

# Install dependencies
pip install -r requirements.txt

# Launch the application
python main.py
```

**Windows shortcut:** double-click `launch.bat` after dependencies are installed.

---

## Repository Structure

```
Multi-Modal-Scanner_Standalone/
├── README.md
├── requirements.txt
├── main.py                     # Application entry point and GUI
├── engine.py                   # Assessment execution engine
├── controls.py                 # Controls library loader
├── detector.py                 # Target type detection
├── scanners.py                 # Shared scanner utilities
├── agent_scanner.py            # AI Agent assessment scanner
├── api_scanner.py              # API vulnerability scanner
├── code_scanner.py             # Source code review scanner
├── os_scanner.py               # OS & software scanner (Windows/Linux)
├── reporter.py                 # Report generation and prior report import
├── db.py                       # SQLite scan history management
├── gui/                        # PyQt6 GUI components
├── launch.bat                  # Windows launcher
└── run_app.bat                 # Windows run script
```

*`assessments.db`, `reports/`, and `test_targets/` are excluded from the repository via `.gitignore`.*

---

## Compliance Framework Coverage

Every finding is cross-referenced against **12+ compliance and regulatory frameworks**:

| Framework | Coverage |
|-----------|----------|
| OWASP Top 10 (2025) | All workflows |
| NIST SP 800-53 Rev 5 | All workflows |
| ISO/IEC 27001:2022 | All workflows |
| PCI-DSS v4.0.1 | All workflows |
| SOC 2 Type II | All workflows |
| HIPAA Security Rule | All workflows |
| CMMC v2.0 Level 2 | All workflows |
| DoD Cloud SRG | All workflows |
| FedRAMP Moderate | All workflows |
| SEC/FINRA | All workflows |
| EU DORA | All workflows |
| EU AI Act | All workflows |

---

## Differences from the Claude Code Skill

The Claude Code skill ([Multi-Modal-Scanner](https://github.com/CavenderProjects/Multi-Modal-Scanner)) provides the same core assessment workflows inside Claude Code. The standalone app adds:

| Feature | Claude Code Skill | Standalone App |
|---------|-------------------|----------------|
| Runtime | Claude Code | Python + PyQt6 (desktop) |
| Claude API required | Yes | No |
| Scan history | Per session | SQLite database, persistent |
| Report triage | In report (browser) | In-app triage interface |
| OS & Software assessment | No | Yes |
| Prior report import | No | Yes (FP + notes carryover) |

---

## Limitations and Caveats

This is a **workflow augmentation tool**, not an autonomous security assessment engine.

- The OS & Software scanner runs against the local host only — it does not perform remote network scanning or agent-based discovery
- Output requires review by a qualified security professional before use in any regulatory or audit context
- False-positive evaluation is only as good as the context provided
- It does not replace legal review for risk acceptance decisions with significant regulatory exposure

---

## Part of a Broader AI Governance Practice Portfolio

| Artifact | Status | Description |
|----------|--------|-------------|
| **Multi-Modal-Scanner** | Live | Claude Code skill version — [github.com/CavenderProjects/Multi-Modal-Scanner](https://github.com/CavenderProjects/Multi-Modal-Scanner) |
| **Multi-Modal-Scanner_Standalone** (this repo) | Live | Standalone desktop app — full PyQt6 application, no Claude Code required |
| **AI Risk Assessment Template** | In progress | Maps NIST AI RMF + ISO 42001 controls to GRC language enterprises already use |
| **AI Vendor Risk Questionnaire** | In progress | 25-question due diligence framework for evaluating third-party AI vendors |

---

## Background

**Christopher Cavender, CISSP, CCSP | IAPP AIGP (in progress)**

20 years in information security and GRC. Former Business Information Security Officer at Anywhere Real Estate (Fortune 500); 11 years managing security programs across financial services, healthcare, and real estate. Currently Information Systems Security Manager at Tripoint Solutions. NJ/NYC.

**Connect:** [LinkedIn](https://linkedin.com/in/christopher-cavender-cissp)

---

## Contributing

Contributions welcome, especially from practitioners working in regulated environments with specific HIPAA, NYDFS, PCI, EU AI Act, or other framework-specific context to add. Open an issue or submit a PR.

---

## License

MIT License. Use freely. Attribution appreciated but not required.

---

*Built 2026 · Part of an active AI governance practice portfolio*
