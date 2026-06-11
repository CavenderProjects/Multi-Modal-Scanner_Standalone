"""Generate test HTML reports for every assessment type.

Run from the pen-tester/standalone directory:
    python make_test_reports.py

Outputs to pen-tester/test-reports/:
  - test-report-website.html
  - test-report-api.html
  - test-report-code-review.html
  - test-report-interconnected.html
  - test-report-os.html
  - test-report-fps.html   (website report with two controls pre-marked FP)
"""

import json
import os
import uuid
from datetime import datetime

STANDALONE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR     = os.path.join(os.path.dirname(STANDALONE_DIR), "assets")
OUT_DIR        = os.path.join(os.path.dirname(STANDALONE_DIR), "test-reports")
os.makedirs(OUT_DIR, exist_ok=True)

TEMPLATES = {
    'website':        'report-template.html',
    'api':            'api-report-template.html',
    'code_review':    'code-review-report-template.html',
    'interconnected': 'interconnected-report-template.html',
    'os':             'report-template.html',
}

TITLES = {
    'website':        'Security Assessment Report',
    'api':            'API Security Assessment',
    'code_review':    'Code Review Security Assessment',
    'interconnected': 'Interconnected Systems Security Assessment',
    'os':             'OS & Software Security Assessment',
}


# ── Control sets per assessment type ─────────────────────────────────────────

WEBSITE_CONTROLS = [
    {
        "id": "AUTH-001", "name": "Multi-factor authentication enforcement",
        "family": "AUTH", "status": "NON_COMPLIANT", "severity": "CRITICAL",
        "cia": "C, I", "tier": "automatic_confirmation",
        "evidence": "MFA is not enforced for any user accounts. Scanner confirmed zero MFA policies active via /api/v1/auth/policies. 47 active accounts have password-only authentication.",
        "finding": "MFA not enforced",
        "remediation": "Enable MFA enforcement in Identity Provider settings. Require TOTP or hardware key for all accounts.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "frameworks": ["NIST 800-53 IA-2"], "source": "auth_scanner",
    },
    {
        "id": "TLS-001", "name": "TLS 1.2+ enforcement",
        "family": "CRYPTO", "status": "NON_COMPLIANT", "severity": "HIGH",
        "cia": "C, I", "tier": "automatic_confirmation",
        "evidence": "TLS 1.0 accepted on port 443. Server negotiated TLS 1.0 in test handshake. PCI DSS 3.2.1 requires TLS 1.2 minimum.",
        "finding": "Legacy TLS versions accepted",
        "remediation": "Disable TLS 1.0 and 1.1. Set SSLProtocol TLSv1.2 TLSv1.3 only.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": {"score": 7.4, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "frameworks": ["PCI DSS 4.2.1"], "source": "tls_scanner",
    },
    {
        "id": "HDR-003", "name": "Security headers — Content-Security-Policy",
        "family": "WEBCONFIG", "status": "NON_COMPLIANT", "severity": "MEDIUM",
        "cia": "C", "tier": "automatic_confirmation",
        "evidence": "Content-Security-Policy header absent on all tested endpoints. X-Frame-Options: missing. X-Content-Type-Options: present (good).",
        "finding": "Missing CSP header",
        "remediation": "Add Content-Security-Policy header. Start with strict-dynamic + nonce. Add X-Frame-Options: DENY.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": None, "frameworks": [], "source": "header_scanner",
    },
    {
        "id": "ACC-005", "name": "Privileged access review",
        "family": "ACCESS", "status": "NEEDS_REVIEW", "severity": "HIGH",
        "cia": "C, I, A", "tier": "review_required",
        "evidence": "14 accounts have admin-level permissions. Last access review: 8 months ago (policy: quarterly). Review INC-4421.",
        "finding": "Access review overdue",
        "remediation": "Conduct privileged access review. Disable or reprovision stale accounts.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "INDIRECT",
        "cvss": None, "frameworks": ["SOC 2 CC6.3"], "source": "iam_scanner",
    },
    {
        "id": "PROC-001", "name": "Incident response plan — annual test",
        "family": "PROCESS", "status": "NOT_TESTED", "severity": "HIGH",
        "cia": "C, I, A", "tier": "manual_confirmation",
        "evidence": "Test procedure:\n1. Request evidence of tabletop exercise or live drill from last 12 months\n2. Confirm exercise covered detection, containment, eradication, recovery\n3. Review after-action report\n4. Verify contact list is current (< 90 days)\n5. Confirm escalation paths tested including executive notification",
        "finding": "", "remediation": "Conduct annual IR tabletop exercise. Document results.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "NONE",
        "cvss": None, "frameworks": ["NIST 800-53 IR-3"], "source": "manual",
    },
    {
        "id": "CRYPTO-002", "name": "Data at rest encryption",
        "family": "CRYPTO", "status": "COMPLIANT", "severity": "HIGH",
        "cia": "C", "tier": "automatic_confirmation",
        "evidence": "AES-256 encryption confirmed on all database volumes. AWS RDS encryption enabled. S3 bucket SSE enabled.",
        "finding": "", "remediation": "",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": None, "frameworks": [], "source": "cloud_scanner",
    },
]

API_CONTROLS = [
    {
        "id": "API-AUTH-001", "name": "API key rotation enforcement",
        "family": "AUTH", "status": "NON_COMPLIANT", "severity": "HIGH",
        "cia": "C, I", "tier": "automatic_confirmation",
        "evidence": "23 of 31 active API keys have not been rotated in over 365 days. Oldest key: 847 days old (created 2022-01-04). Key expiry policy: not enforced. Tested via GET /api/v2/admin/keys.",
        "finding": "Stale API keys — no rotation policy enforced",
        "remediation": "Implement mandatory API key rotation (90-day maximum). Revoke keys older than 365 days immediately. Enable key expiry on issuance.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "frameworks": ["NIST 800-53 IA-5"], "source": "api_scanner",
    },
    {
        "id": "API-RATE-001", "name": "Rate limiting on authentication endpoints",
        "family": "RATE", "status": "NON_COMPLIANT", "severity": "HIGH",
        "cia": "C, A", "tier": "automatic_confirmation",
        "evidence": "POST /api/v2/auth/login: 1,000 requests in 60 seconds completed with no throttling. No 429 responses observed. No CAPTCHA triggered. Account lockout: not implemented.",
        "finding": "No rate limiting on login endpoint — brute force possible",
        "remediation": "Implement rate limiting: 5 failed attempts per minute per IP, then exponential backoff. Add account lockout after 10 failures.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "frameworks": ["OWASP API4"], "source": "api_scanner",
    },
    {
        "id": "API-INPUT-002", "name": "Input validation — SQL injection protection",
        "family": "INPUT", "status": "NON_COMPLIANT", "severity": "CRITICAL",
        "cia": "C, I", "tier": "automatic_confirmation",
        "evidence": "GET /api/v2/users?id=1 OR 1=1 returned 200 with full user list (n=247). Parameterised queries not used in UserController.findById(). Confirmed via error-based SQLi probe returning DB version string.",
        "finding": "SQL injection in /api/v2/users endpoint",
        "remediation": "Use parameterised queries or ORM. Never interpolate user input into SQL strings. Deploy WAF rule as interim mitigation.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "frameworks": ["OWASP API8"], "source": "api_scanner",
    },
    {
        "id": "API-AUTHZ-003", "name": "Object-level authorisation (BOLA/IDOR)",
        "family": "AUTHZ", "status": "NEEDS_REVIEW", "severity": "HIGH",
        "cia": "C", "tier": "review_required",
        "evidence": "Automated probe found that changing user_id parameter returns data for other users in some endpoints. Manual review required to determine full scope — some endpoints appear protected, others may not be.",
        "finding": "Possible BOLA — requires manual verification",
        "remediation": "Enforce object-level authorisation on every data-returning endpoint. Validate that requesting user owns or has rights to the requested object.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": None, "frameworks": ["OWASP API1"], "source": "api_scanner",
    },
    {
        "id": "API-PROC-001", "name": "API deprecation and versioning policy",
        "family": "LIFECYCLE", "status": "NOT_TESTED", "severity": "MEDIUM",
        "cia": "A", "tier": "manual_confirmation",
        "evidence": "Test procedure:\n1. Request API versioning policy documentation\n2. Verify deprecated endpoints are removed or return 410 Gone\n3. Check sunset headers on v1 endpoints\n4. Confirm consumers have been notified of deprecation timeline\n5. Verify v1 traffic has dropped below 1% before removal",
        "finding": "", "remediation": "Implement versioning policy. Set Sunset headers. Remove deprecated endpoints on schedule.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "NONE",
        "cvss": None, "frameworks": [], "source": "manual",
    },
    {
        "id": "API-TLS-001", "name": "API transport security",
        "family": "CRYPTO", "status": "COMPLIANT", "severity": "HIGH",
        "cia": "C, I", "tier": "automatic_confirmation",
        "evidence": "All API endpoints enforce HTTPS. HTTP→HTTPS redirect active. HSTS header present with max-age=31536000. TLS 1.2 and 1.3 only accepted.",
        "finding": "", "remediation": "",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": None, "frameworks": [], "source": "tls_scanner",
    },
]

CODE_REVIEW_CONTROLS = [
    {
        "id": "CODE-SEC-001", "name": "Hard-coded credentials in source",
        "family": "CODE", "status": "NON_COMPLIANT", "severity": "CRITICAL",
        "cia": "C, I", "tier": "automatic_confirmation",
        "evidence": "Found in src/config/database.js line 14: `password: 'Sup3rS3cr3t!'`\nFound in src/integrations/stripe.js line 3: `apiKey: 'sk_live_xxxxxxxxxxxxxxxxx'`\nFound via gitleaks scan — 2 high-severity secrets detected in working tree.",
        "finding": "Hard-coded credentials in source code",
        "remediation": "Remove secrets from source immediately. Rotate all leaked credentials. Use environment variables or secrets manager. Add pre-commit hook to block future commits.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "frameworks": ["OWASP A02"], "source": "secret_scanner",
    },
    {
        "id": "DEP-001", "name": "Dependency vulnerability — critical CVEs",
        "family": "DEP", "status": "NON_COMPLIANT", "severity": "HIGH",
        "cia": "C, I", "tier": "automatic_confirmation",
        "evidence": "npm audit found:\n- lodash@4.17.15: CVE-2021-23337 (CVSS 7.2) — prototype pollution\n- axios@0.21.1: CVE-2021-3749 (CVSS 7.5) — SSRF\n- express@4.17.1: CVE-2022-24999 (CVSS 7.5) — open redirect\n3 high-severity vulnerabilities in production dependencies.",
        "finding": "Vulnerable dependencies with known CVEs",
        "remediation": "Run `npm audit fix`. Update lodash to ≥4.17.21, axios to ≥0.27.2, express to ≥4.18.2. Add npm audit to CI pipeline.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "INDIRECT",
        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "frameworks": ["OWASP A06"], "source": "dependency_scanner",
    },
    {
        "id": "CODE-SEC-003", "name": "Input sanitisation — XSS prevention",
        "family": "CODE", "status": "NON_COMPLIANT", "severity": "HIGH",
        "cia": "C", "tier": "automatic_confirmation",
        "evidence": "src/views/profile.js line 87: `element.innerHTML = userInput` — unsanitised user data rendered as HTML. Semgrep rule react-dangerously-set-innerhtml triggered on 4 locations. No DOMPurify or equivalent in use.",
        "finding": "Reflected XSS via unsanitised innerHTML assignment",
        "remediation": "Replace innerHTML with textContent for user data. If HTML rendering required, use DOMPurify.sanitize(). Add semgrep to CI to block future violations.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
        "frameworks": ["OWASP A03"], "source": "sast_scanner",
    },
    {
        "id": "CODE-SEC-010", "name": "Cryptographic algorithm selection",
        "family": "CRYPTO", "status": "NEEDS_REVIEW", "severity": "MEDIUM",
        "cia": "C", "tier": "review_required",
        "evidence": "src/auth/token.js uses MD5 for token hashing (line 23). MD5 is cryptographically broken. However, the specific use case (non-security checksum for cache busting) may be acceptable. Manual review needed to confirm whether the output has security implications.",
        "finding": "MD5 in use — context determines severity",
        "remediation": "Replace MD5 with SHA-256 or SHA-3 for any security-relevant hashing. Document acceptable use of MD5 for non-security checksums.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "INDIRECT",
        "cvss": None, "frameworks": [], "source": "sast_scanner",
    },
    {
        "id": "DEP-PROC-001", "name": "Software Bill of Materials (SBOM) generation",
        "family": "PROCESS", "status": "NOT_TESTED", "severity": "MEDIUM",
        "cia": "I", "tier": "manual_confirmation",
        "evidence": "Test procedure:\n1. Confirm SBOM is generated as part of CI/CD pipeline\n2. Verify SBOM format: SPDX or CycloneDX\n3. Check SBOM is published alongside each release artifact\n4. Confirm SBOM includes all transitive dependencies\n5. Verify SBOM is consumed by vulnerability tracking system",
        "finding": "", "remediation": "Integrate `syft` or `cdxgen` into CI pipeline. Publish SBOM with each release.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "NONE",
        "cvss": None, "frameworks": ["NIST SSDF"], "source": "manual",
    },
    {
        "id": "DEP-002", "name": "No known malicious packages",
        "family": "DEP", "status": "COMPLIANT", "severity": "CRITICAL",
        "cia": "C, I, A", "tier": "automatic_confirmation",
        "evidence": "Socket.dev scan: 0 malware alerts, 0 typosquat candidates flagged. All 312 dependencies verified against known-safe registry. No install scripts with network access detected.",
        "finding": "", "remediation": "",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": None, "frameworks": [], "source": "supply_chain_scanner",
    },
]

CROSS_SYSTEM_CONTROLS = [
    {
        "id": "XSYS-IAM-001", "name": "Shared service account credentials",
        "family": "IAM", "status": "NON_COMPLIANT", "severity": "CRITICAL",
        "cia": "C, I, A", "tier": "automatic_confirmation",
        "evidence": "Service account `svc-deploy` credentials are used across 4 systems: web-prod, api-prod, db-admin, monitoring. Password last changed 612 days ago. Single compromise gives lateral movement across all systems. Verified via secrets manager audit.",
        "finding": "Single shared credential used across multiple production systems",
        "remediation": "Create separate service accounts per system. Rotate all shared credentials immediately. Implement workload identity federation where possible.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": {"score": 9.0, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"},
        "frameworks": ["NIST 800-53 AC-2"], "source": "iam_scanner",
    },
    {
        "id": "XSYS-NET-001", "name": "East-west traffic encryption between services",
        "family": "NETWORK", "status": "NON_COMPLIANT", "severity": "HIGH",
        "cia": "C, I", "tier": "automatic_confirmation",
        "evidence": "Traffic between api-prod and db-prod is unencrypted (plaintext TCP port 5432). Captured sample with tcpdump on internal network segment — customer PII visible in transit. mTLS not configured on service mesh.",
        "finding": "Database traffic unencrypted on internal network",
        "remediation": "Enable SSL/TLS on PostgreSQL connections. Configure mTLS via service mesh (Istio/Linkerd). Treat internal network as untrusted.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "INDIRECT",
        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "frameworks": ["NIST 800-53 SC-8"], "source": "network_scanner",
    },
    {
        "id": "XSYS-LOG-001", "name": "Centralised audit logging — coverage",
        "family": "LOG", "status": "NEEDS_REVIEW", "severity": "HIGH",
        "cia": "I", "tier": "review_required",
        "evidence": "SIEM receiving logs from: web-prod ✓, api-prod ✓, monitoring ✓. NOT receiving logs from: db-admin, legacy-batch. Unknown: internal-tools (no log agent visible). Manual verification of log pipeline completeness required.",
        "finding": "Incomplete log coverage — 2+ systems not forwarding to SIEM",
        "remediation": "Deploy log agent to db-admin and legacy-batch. Audit all systems in scope against SIEM source list. Set alert for 24h silence from any expected source.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "INDIRECT",
        "cvss": None, "frameworks": ["SOC 2 CC7.2"], "source": "siem_scanner",
    },
    {
        "id": "XSYS-PROC-001", "name": "Cross-system change management",
        "family": "PROCESS", "status": "NOT_TESTED", "severity": "MEDIUM",
        "cia": "I, A", "tier": "manual_confirmation",
        "evidence": "Test procedure:\n1. Request change records for last 90 days from ITSM\n2. Verify interconnected system changes have impact analysis covering all affected systems\n3. Confirm rollback plan documented for each change\n4. Verify peer approval obtained before production deployment\n5. Check post-change validation steps completed and logged",
        "finding": "", "remediation": "Enforce interconnected system change review in ITSM. Require impact analysis and rollback plan for all changes touching >1 system.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "NONE",
        "cvss": None, "frameworks": ["ITIL", "SOC 2 CC8.1"], "source": "manual",
    },
    {
        "id": "XSYS-IAM-002", "name": "Consistent access revocation across systems",
        "family": "IAM", "status": "COMPLIANT", "severity": "HIGH",
        "cia": "C", "tier": "automatic_confirmation",
        "evidence": "Offboarding automation verified: HRIS termination event triggers automated account disable across AD, GitHub, AWS IAM, and Jira within 15 minutes. Tested with 3 sample terminations from last 90 days — all completed within SLA.",
        "finding": "", "remediation": "",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "DIRECT",
        "cvss": None, "frameworks": ["SOC 2 CC6.2"], "source": "iam_scanner",
    },
]

OS_CONTROLS = [
    {
        "id": "PATCH-001", "name": "OS security updates current",
        "family": "PATCH", "status": "NON_COMPLIANT", "severity": "CRITICAL",
        "cia": "C, I, A", "tier": "automatic_confirmation",
        "evidence": "Windows Update: 3 critical and 7 important security updates pending installation.\nOldest pending: KB5031845 (2023-10-10, CVSS 9.8 — Windows CLFS driver privilege escalation).\nAutomatic updates: Disabled (policy override). Last successful update install: 2023-08-14.",
        "finding": "3 critical OS security updates uninstalled — oldest 58 days",
        "remediation": "Install all pending security updates immediately. Enable Windows Update for Business with automatic installation of security updates. Establish 7-day SLA for critical patches.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "LOCAL",
        "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
        "frameworks": ["CIS Control 7.3", "NIST 800-53 SI-2"], "source": "os_version_scanner",
    },
    {
        "id": "PATCH-003", "name": "Installed software CVE exposure",
        "family": "PATCH", "status": "NON_COMPLIANT", "severity": "HIGH",
        "cia": "C, I, A", "tier": "automatic_confirmation",
        "evidence": "NVD query results for installed software:\n  OpenSSL 1.1.1t: CVE-2023-0286 (CVSS 7.4) — X.400 address type confusion\n  Python 3.9.7: CVE-2023-24329 (CVSS 7.5) — urllib URL parsing bypass\n  Git 2.37.0: CVE-2022-39253 (CVSS 5.5) — local clone submodule path traversal\n2 high-severity CVEs in installed software. Updated versions available for all affected packages.",
        "finding": "2 high-severity CVEs in installed software",
        "remediation": "Update OpenSSL to ≥3.0.8. Update Python to ≥3.11.4. Update Git to ≥2.41.0. Subscribe to vendor security advisories.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "INDIRECT",
        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "frameworks": ["CIS Control 7.4", "NIST 800-53 RA-5"], "source": "software_cve_scanner",
    },
    {
        "id": "EOL-001", "name": "Operating system end-of-life status",
        "family": "EOL", "status": "COMPLIANT", "severity": "CRITICAL",
        "cia": "C, I, A", "tier": "automatic_confirmation",
        "evidence": "OS: Windows 11 Pro 23H2 (Build 22631.2715). Microsoft mainstream support end: 2027-10-14. Extended support end: 2027-10-14. Status: SUPPORTED. Days until EOL: 1,405.",
        "finding": "", "remediation": "",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "LOCAL",
        "cvss": None, "frameworks": ["NIST 800-53 SA-22"], "source": "os_version_scanner",
    },
    {
        "id": "SVCCONFIG-002", "name": "Unnecessary and insecure services disabled",
        "family": "SVCCONFIG", "status": "NON_COMPLIANT", "severity": "HIGH",
        "cia": "C, I, A", "tier": "automatic_confirmation",
        "evidence": "Running services flagged as insecure or unnecessary:\n  - Print Spooler (Spooler): RUNNING — not a print server; exploitable via PrintNightmare (CVE-2021-34527)\n  - Telnet Client feature: INSTALLED — cleartext remote access protocol\n  - SMBv1 (LanmanServer with NegotiateProtocol SMB 1.0): ENABLED — vulnerable to EternalBlue (CVE-2017-0144)\n3 insecure services/features active.",
        "finding": "3 insecure services running: Spooler, Telnet, SMBv1",
        "remediation": "Stop and disable Print Spooler on non-print servers: sc config Spooler start=disabled. Remove Telnet Client feature. Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "NETWORK",
        "cvss": {"score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"},
        "frameworks": ["CIS Control 4.8", "NIST 800-53 CM-7"], "source": "services_scanner",
    },
    {
        "id": "SVCEXPOSE-001", "name": "Listening network services minimized",
        "family": "SVCEXPOSE", "status": "NEEDS_REVIEW", "severity": "MEDIUM",
        "cia": "C, I, A", "tier": "automatic_confirmation",
        "evidence": "Listening TCP ports (all interfaces):\n  Expected: 80 (HTTP), 443 (HTTPS), 3389 (RDP), 5985 (WinRM)\n  Unexpected: 27017 (MongoDB — bound 0.0.0.0, no auth), 8888 (Jupyter Notebook — token auth unknown)\n2 unexpected listening ports require review. MongoDB on 0.0.0.0 without confirmed auth is high risk.",
        "finding": "MongoDB and Jupyter Notebook listening on unexpected ports — review required",
        "remediation": "Bind MongoDB to 127.0.0.1 or a specific internal IP. Verify Jupyter token authentication is enabled. Document all authorized listening ports.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "NETWORK",
        "cvss": None, "frameworks": ["CIS Control 4.4", "NIST 800-53 CM-7"], "source": "services_scanner",
    },
    {
        "id": "PATCH-002", "name": "Vulnerability patch SLA compliance",
        "family": "PATCH", "status": "NOT_TESTED", "severity": "HIGH",
        "cia": "C, I, A", "tier": "manual_confirmation",
        "evidence": "Test procedure:\n1. Request the vulnerability management or patch management policy document.\n2. Verify severity-based patching timelines are defined in writing (critical ≤72h, high ≤7d, medium ≤30d).\n3. Review the last 90 days of patch history and confirm critical/high CVEs were remediated within the stated SLA.\n4. Identify any CVEs that exceeded the SLA and verify formal exception approval.\n5. Confirm policy assigns an owner for tracking patch compliance.",
        "finding": "", "remediation": "Define and publish a patch SLA policy. Implement automated tracking to flag SLA breaches.",
        "mitigation": "NO", "mitigationDesc": "", "reachability": "NONE",
        "cvss": None, "frameworks": ["CIS Control 7.1", "NIST 800-53 SI-2(3)"], "source": "manual",
    },
]

ALL_TYPES = {
    'website':        ('api.example.com',        WEBSITE_CONTROLS),
    'api':            ('api.example.com/v2',      API_CONTROLS),
    'code_review':    ('github.com/org/app-repo', CODE_REVIEW_CONTROLS),
    'interconnected': ('prod-environment',        CROSS_SYSTEM_CONTROLS),
    'os':             ('localhost',               OS_CONTROLS),
}


def render(controls, title, target, report_id, template_name):
    tmpl_path = os.path.join(ASSETS_DIR, template_name)
    with open(tmpl_path, 'r', encoding='utf-8') as f:
        tmpl = f.read()

    nc  = [c for c in controls if c['status'] == 'NON_COMPLIANT']
    sev = lambda s: sum(1 for c in nc if c['severity'] == s)

    subs = {
        '{{REPORT_TITLE}}':        title,
        '{{TARGET_NAME}}':         target,
        '{{TOTAL_CONTROLS}}':      str(len(controls)),
        '{{FRAMEWORK}}':           'All frameworks',
        '{{NON_COMPLIANT_COUNT}}': str(len(nc)),
        '{{CRIT_COUNT}}':          str(sev('CRITICAL')),
        '{{HIGH_COUNT}}':          str(sev('HIGH')),
        '{{MED_COUNT}}':           str(sev('MEDIUM')),
        '{{LOW_COUNT}}':           str(sev('LOW')),
        '{{INFO_COUNT}}':          str(sev('INFORMATIONAL')),
        '{{CONTROLS_JSON}}':       json.dumps(controls, indent=2),
        '{{REPORT_DATE}}':         datetime.now().strftime('%Y-%m-%d %H:%M'),
        '{{REPORT_ID}}':           report_id,
    }
    html = tmpl
    for k, v in subs.items():
        html = html.replace(k, v)
    return html


# ── Generate one report per assessment type ───────────────────────────────────
for atype, (target, controls) in ALL_TYPES.items():
    rid  = str(uuid.uuid4())[:8]
    tmpl = TEMPLATES[atype]
    title = TITLES[atype]
    html = render(controls, title, target, rid, tmpl)
    out  = os.path.join(OUT_DIR, f'test-report-{atype.replace("_", "-")}.html')
    with open(out, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f'Written: {out}')

# ── False-positive variant (website, AUTH-001 pre-suppressed) ─────────────────
fp_controls = []
for c in WEBSITE_CONTROLS:
    cc = dict(c)
    if cc['id'] == 'AUTH-001':
        cc['mitigation']    = 'YES'
        cc['mitigationDesc'] = 'Compensating control: hardware tokens enforced via physical access policy. Accepted risk logged in RR-0042.'
        cc['status']        = 'FALSE_POSITIVE'
    fp_controls.append(cc)

html_fp = render(fp_controls, 'Security Assessment Report', 'api.example.com',
                 str(uuid.uuid4())[:8], TEMPLATES['website'])
out_fp = os.path.join(OUT_DIR, 'test-report-fps.html')
with open(out_fp, 'w', encoding='utf-8') as f:
    f.write(html_fp)
print(f'Written: {out_fp}')

print('\nDone. Open any HTML file in a browser to verify.')
