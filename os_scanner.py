"""OS & Software scanner.

Enumerates the local machine's OS version, installed software, running
services, and listening ports.  Checks installed software against the NVD
CVE database and flags known-vulnerable packages, end-of-life OS versions,
unnecessary services, and exposed network ports.

Returns a list of ScanResult objects compatible with the existing engine.
"""

import os
import sys
import json
import platform
import subprocess
import time
import urllib.request
import urllib.parse
from datetime import datetime, date
from dataclasses import dataclass

# Import ScanResult from sibling module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanners import ScanResult


# ── NVD API ───────────────────────────────────────────────────────────────────

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_CACHE: dict = {}          # keyword → list of CVE dicts (in-memory per run)
_NVD_LAST_REQUEST = 0.0        # epoch seconds of last NVD request
_NVD_RATE_DELAY = 0.7          # seconds between NVD requests (stay under 5/sec)


def _nvd_query(keyword: str, api_key: str = None) -> list:
    """Query NVD for CVEs matching keyword.  Returns list of vulnerability dicts."""
    global _NVD_LAST_REQUEST

    if keyword in _NVD_CACHE:
        return _NVD_CACHE[keyword]

    # Rate-limit
    elapsed = time.time() - _NVD_LAST_REQUEST
    if elapsed < _NVD_RATE_DELAY:
        time.sleep(_NVD_RATE_DELAY - elapsed)

    params = {
        'keywordSearch': keyword,
        'resultsPerPage': 10,
    }
    url = NVD_API_BASE + '?' + urllib.parse.urlencode(params)
    headers = {'User-Agent': 'SecurityAssessmentTool/1.0'}
    if api_key:
        headers['apiKey'] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())
            vulns = data.get('vulnerabilities', [])
            _NVD_CACHE[keyword] = vulns
            _NVD_LAST_REQUEST = time.time()
            return vulns
    except Exception:
        _NVD_LAST_REQUEST = time.time()
        return []


def _highest_cvss(vulns: list) -> tuple:
    """Return (max_score, max_vector, cve_id) from a list of NVD vulnerability dicts."""
    best_score = 0.0
    best_vector = ""
    best_id = ""
    for v in vulns:
        cve = v.get('cve', {})
        cve_id = cve.get('id', '')
        metrics = cve.get('metrics', {})
        # Try CVSSv3.1 first, then v3.0, then v2
        for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            for m in metrics.get(key, []):
                data = m.get('cvssData', {})
                score = float(data.get('baseScore', 0))
                vector = data.get('vectorString', '')
                if score > best_score:
                    best_score = score
                    best_vector = vector
                    best_id = cve_id
    return best_score, best_vector, best_id


def _cve_summary(vulns: list, max_items: int = 5) -> str:
    """Build a short summary string listing top CVEs."""
    lines = []
    scored = []
    for v in vulns:
        cve = v.get('cve', {})
        cve_id = cve.get('id', '')
        desc_list = cve.get('descriptions', [])
        desc = next((d['value'] for d in desc_list if d.get('lang') == 'en'), '')
        metrics = cve.get('metrics', {})
        score = 0.0
        for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            for m in metrics.get(key, []):
                score = max(score, float(m.get('cvssData', {}).get('baseScore', 0)))
        scored.append((score, cve_id, desc[:120]))
    scored.sort(key=lambda x: x[0], reverse=True)
    for score, cid, desc in scored[:max_items]:
        lines.append(f"  {cid} (CVSS {score:.1f}): {desc}")
    return '\n'.join(lines)


# ── OS information helpers ────────────────────────────────────────────────────

def _os_info() -> dict:
    """Return dict with os_name, os_version, os_build, os_full."""
    info = {
        'os_name':    platform.system(),
        'os_version': platform.version(),
        'os_release': platform.release(),
        'os_full':    platform.platform(),
        'machine':    platform.machine(),
    }
    if sys.platform == 'win32':
        import winreg
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            )
            info['product_name'] = winreg.QueryValueEx(key, 'ProductName')[0]
            try:
                info['display_version'] = winreg.QueryValueEx(key, 'DisplayVersion')[0]
            except FileNotFoundError:
                info['display_version'] = winreg.QueryValueEx(key, 'ReleaseId')[0]
            info['build_number'] = winreg.QueryValueEx(key, 'CurrentBuildNumber')[0]
            winreg.CloseKey(key)
        except Exception:
            pass
    return info


# ── EOL data ─────────────────────────────────────────────────────────────────

# EOL dates (YYYY-MM-DD). Keys are lowercase substrings to match against
# the platform string.  More specific keys are checked first.
_OS_EOL = {
    # Windows (check by product name substring)
    'windows 7':                '2020-01-14',
    'windows 8.1':              '2023-01-10',
    'windows 8':                '2016-01-12',
    'windows 10':               None,           # version-dependent — checked separately
    'windows server 2008':      '2020-01-14',
    'windows server 2012':      '2023-10-10',
    'windows server 2016':      '2027-01-12',
    'windows server 2019':      '2029-01-09',
    'windows server 2022':      '2031-10-14',
    # Windows 10 feature versions (check display_version)
    'win10-21h1':               '2022-12-13',
    'win10-21h2':               '2023-06-13',
    'win10-22h2':               '2025-10-14',   # still supported as of 2026
    'win10-1909':               '2021-05-11',
    'win10-20h2':               '2022-05-10',
    # Ubuntu
    'ubuntu 16.04':             '2021-04-30',
    'ubuntu 18.04':             '2023-04-30',
    'ubuntu 20.04':             '2025-04-30',
    'ubuntu 22.04':             '2027-04-30',
    'ubuntu 24.04':             '2029-04-30',
    # Debian
    'debian 9':                 '2022-06-30',
    'debian 10':                '2024-06-30',
    'debian 11':                '2026-06-30',
    'debian 12':                '2028-06-30',
    # CentOS / RHEL
    'centos 6':                 '2020-11-30',
    'centos 7':                 '2024-06-30',
    'centos 8':                 '2021-12-31',
    'red hat enterprise linux 7': '2024-06-30',
    'red hat enterprise linux 8': '2029-05-31',
    # macOS
    'macos 12':                 '2025-01-01',   # approximate
    'macos 11':                 '2024-01-01',
    'macos 10.15':              '2022-10-24',
}

_RISKY_SERVICES_WIN = {
    'TlntSvr':    'Telnet server (cleartext remote shell)',
    'FTPSVC':     'IIS FTP server (cleartext file transfer)',
    'tftpd32':    'TFTP server (cleartext, no auth)',
    'SNMP':       'SNMP v1/v2 (cleartext community strings)',
    'RemoteRegistry': 'Remote Registry (allows remote registry edits)',
    'Spooler':    'Print Spooler (CVE-2021-34527 PrintNightmare and variants)',
    'RasMan':     'Remote Access Service (check if required)',
    'WinRM':      'Windows Remote Management — verify access restriction',
}

_RISKY_SERVICES_LINUX = {
    'telnetd':    'Telnet daemon (cleartext remote shell)',
    'vsftpd':     'FTP server (cleartext file transfer)',
    'proftpd':    'ProFTPD server (cleartext file transfer)',
    'tftpd':      'TFTP server (cleartext, no auth)',
    'rshd':       'RSH daemon (cleartext remote shell)',
    'rexecd':     'Rexec daemon (cleartext remote execution)',
    'snmpd':      'SNMP daemon — check for v1/v2 community strings',
    'xinetd':     'inetd/xinetd super-server — audit enabled services',
}

# Ports that are normally fine to have open (excluded from "unexpected port" check)
_EXPECTED_PORTS = {
    22, 80, 443, 3389,         # SSH, HTTP, HTTPS, RDP
    8080, 8443, 8888,          # alt web
    53,                        # DNS (local resolver)
    135, 139, 445,             # Windows SMB/RPC (internal)
    5985, 5986,                # WinRM (flagged separately by SVCEXPOSE-002)
}


# ── Inventory helpers ─────────────────────────────────────────────────────────

def _get_windows_software() -> list:
    """Return list of (name, version) tuples from Windows registry."""
    ps_cmd = (
        "Get-ItemProperty "
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
        "-ErrorAction SilentlyContinue "
        "| Where-Object {$_.DisplayName -and $_.DisplayName.Trim() -ne ''} "
        "| Select-Object DisplayName,DisplayVersion "
        "| ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30
        )
        items = json.loads(result.stdout.strip())
        if isinstance(items, dict):
            items = [items]
        return [
            (i.get('DisplayName', '').strip(), i.get('DisplayVersion', '') or '')
            for i in items
            if i.get('DisplayName', '').strip()
        ]
    except Exception:
        return []


def _get_linux_software() -> list:
    """Return list of (name, version) tuples from dpkg or rpm."""
    packages = []
    # Try dpkg (Debian/Ubuntu)
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.strip().split(' ', 1)
                if len(parts) == 2:
                    packages.append((parts[0], parts[1]))
            return packages
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Try rpm (RHEL/CentOS/Fedora)
    try:
        result = subprocess.run(
            ["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}\n"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.strip().split(' ', 1)
                if len(parts) == 2:
                    packages.append((parts[0], parts[1]))
            return packages
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


def _get_pending_windows_updates() -> tuple:
    """Return (pending_count, error_msg).  pending_count is None on error."""
    ps_cmd = (
        "try {"
        "  $s = New-Object -ComObject Microsoft.Update.Session;"
        "  $r = $s.CreateUpdateSearcher().Search('IsInstalled=0 and Type=\"Software\"');"
        "  $r.Updates.Count"
        "} catch { Write-Output 'ERROR' }"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=45
        )
        out = result.stdout.strip()
        if out == 'ERROR' or not out.isdigit():
            return None, "Windows Update COM query failed (may need elevation)"
        return int(out), None
    except Exception as e:
        return None, str(e)


def _get_pending_linux_updates() -> tuple:
    """Return (pending_count, error_msg)."""
    # apt
    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True, text=True, timeout=20,
            env={**os.environ, 'LANG': 'C'}
        )
        lines = [l for l in result.stdout.splitlines()
                 if l and not l.startswith('Listing')]
        return len(lines), None
    except FileNotFoundError:
        pass
    # yum / dnf
    try:
        result = subprocess.run(
            ["yum", "check-update", "--quiet"],
            capture_output=True, text=True, timeout=30
        )
        # yum returns exit code 100 when updates available, 0 when none
        lines = [l for l in result.stdout.splitlines() if l.strip()]
        return len(lines), None
    except FileNotFoundError:
        pass
    return None, "No supported package manager found"


def _get_listening_ports() -> list:
    """Return list of (port, proto, pid, process_name) for listening sockets."""
    ports = []
    if sys.platform == 'win32':
        try:
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=10
            )
            # Parse: Proto  Local Address  Foreign Address  State  PID
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and 'LISTENING' in line:
                    proto = parts[0]       # TCP
                    local = parts[1]       # 0.0.0.0:PORT or [::]:PORT
                    pid = parts[-1] if parts[-1].isdigit() else '0'
                    port_str = local.rsplit(':', 1)[-1]
                    if port_str.isdigit():
                        ports.append((int(port_str), proto, int(pid), ''))
        except Exception:
            pass
    else:
        try:
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines()[1:]:  # skip header
                parts = line.split()
                if len(parts) >= 4:
                    local = parts[3]
                    port_str = local.rsplit(':', 1)[-1]
                    if port_str.isdigit():
                        ports.append((int(port_str), 'TCP', 0, ''))
        except Exception:
            pass
        # Try netstat as fallback
        if not ports:
            try:
                result = subprocess.run(
                    ["netstat", "-tlnp"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    if 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            local = parts[3]
                            port_str = local.rsplit(':', 1)[-1]
                            if port_str.isdigit():
                                ports.append((int(port_str), 'TCP', 0, ''))
            except Exception:
                pass
    return ports


def _get_running_services_windows() -> list:
    """Return list of running service names on Windows."""
    ps_cmd = (
        "Get-Service | Where-Object {$_.Status -eq 'Running'} "
        "| Select-Object -ExpandProperty Name"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        return [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def _get_running_services_linux() -> list:
    """Return list of active service names on Linux."""
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running",
             "--plain", "--no-legend"],
            capture_output=True, text=True, timeout=10
        )
        services = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts:
                name = parts[0].replace('.service', '')
                services.append(name)
        return services
    except Exception:
        return []


# ── Individual scanner classes ────────────────────────────────────────────────

class OSVersionScanner:
    """Checks OS patch level and EOL status."""
    name = "os-version"
    description = "OS version and patch level"

    def scan(self, target: str, progress_callback=None) -> list:
        if progress_callback:
            progress_callback(self.name, self.description, 'running', [])

        results = []
        info = _os_info()
        os_full = info.get('os_full', platform.platform())
        os_lower = os_full.lower()
        product_name = info.get('product_name', '').lower()

        # ── PATCH-001: Pending OS security updates ──
        if sys.platform == 'win32':
            pending, err = _get_pending_windows_updates()
        else:
            pending, err = _get_pending_linux_updates()

        if pending is None:
            results.append(ScanResult(
                scanner=self.name,
                control_id='PATCH-001',
                status='NEEDS_REVIEW',
                severity='HIGH',
                evidence=(
                    f"OS: {os_full}\n"
                    f"Could not query pending updates automatically: {err}\n"
                    f"Manual verification required: check the system's update mechanism "
                    f"for pending security updates."
                ),
                confidence=0.3,
                remediation="Manually verify OS update status and apply all pending security updates.",
            ))
        elif pending == 0:
            results.append(ScanResult(
                scanner=self.name,
                control_id='PATCH-001',
                status='COMPLIANT',
                severity='CRITICAL',
                evidence=f"OS: {os_full}\nNo pending security updates detected.",
                confidence=0.9,
            ))
        else:
            results.append(ScanResult(
                scanner=self.name,
                control_id='PATCH-001',
                status='NON_COMPLIANT',
                severity='CRITICAL',
                evidence=(
                    f"OS: {os_full}\n"
                    f"{pending} pending update{'s' if pending != 1 else ''} detected.\n"
                    f"Unpatched updates increase exposure to known exploits."
                ),
                confidence=0.95,
                cvss_score=7.8,
                cvss_vector='CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
                reachability='INDIRECT',
                remediation="Apply all pending security updates. Enable automatic updates for security patches.",
            ))

        # ── EOL-001: OS end-of-life ──
        eol_date_str = None
        matched_key = None

        # Check product name first (more specific for Windows)
        check_str = product_name or os_lower

        # Windows 10 feature version check
        display_version = info.get('display_version', '')
        if 'windows 10' in check_str and display_version:
            win10_key = f"win10-{display_version.lower()}"
            if win10_key in _OS_EOL:
                eol_date_str = _OS_EOL[win10_key]
                matched_key = win10_key

        if eol_date_str is None:
            for key, eol in sorted(_OS_EOL.items(), key=lambda x: -len(x[0])):
                if key.startswith('win10-'):
                    continue
                if key in check_str or key in os_lower:
                    if eol is not None:
                        eol_date_str = eol
                        matched_key = key
                    break

        if eol_date_str:
            eol_dt = date.fromisoformat(eol_date_str)
            today = date.today()
            if today > eol_dt:
                days_past = (today - eol_dt).days
                results.append(ScanResult(
                    scanner=self.name,
                    control_id='EOL-001',
                    status='NON_COMPLIANT',
                    severity='CRITICAL',
                    evidence=(
                        f"OS: {os_full}\n"
                        f"End-of-life date: {eol_date_str} ({days_past} days ago)\n"
                        f"This OS version no longer receives security updates from the vendor.\n"
                        f"Any newly discovered vulnerabilities will not be patched."
                    ),
                    confidence=0.95,
                    cvss_score=9.8,
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    reachability='DIRECT',
                    remediation=f"Upgrade to a supported OS version immediately. {os_full} reached end-of-life on {eol_date_str}.",
                ))
            else:
                months_remaining = max(0, (eol_dt - today).days // 30)
                sev = 'HIGH' if months_remaining < 12 else 'INFORMATIONAL'
                status = 'NEEDS_REVIEW' if months_remaining < 6 else 'COMPLIANT'
                results.append(ScanResult(
                    scanner=self.name,
                    control_id='EOL-001',
                    status=status,
                    severity=sev,
                    evidence=(
                        f"OS: {os_full}\n"
                        f"End-of-life date: {eol_date_str} ({months_remaining} months remaining)\n"
                        f"OS is currently within vendor support lifecycle."
                        + ("\nWarning: less than 6 months until end-of-support. Begin upgrade planning." if months_remaining < 6 else "")
                    ),
                    confidence=0.9,
                ))
        else:
            results.append(ScanResult(
                scanner=self.name,
                control_id='EOL-001',
                status='NEEDS_REVIEW',
                severity='MEDIUM',
                evidence=(
                    f"OS: {os_full}\n"
                    f"OS version not found in local EOL database.\n"
                    f"Manual verification required: check vendor lifecycle page for support status."
                ),
                confidence=0.3,
                remediation="Check vendor lifecycle page to confirm OS is within support period.",
            ))

        if progress_callback:
            progress_callback(self.name, self.description, 'done', results)

        return results


class SoftwareCVEScanner:
    """Enumerates installed software and checks against NVD for known CVEs."""
    name = "software-cve"
    description = "Installed software CVE check (NVD)"

    # High-value software to prioritise for CVE lookup (exact name substrings, lowercase)
    PRIORITY_KEYWORDS = [
        'chrome', 'firefox', 'edge', 'safari', 'opera',        # browsers
        'java', 'python', 'node', 'ruby', 'perl', 'php',        # runtimes
        'openssl', 'openssh', 'putty',                          # crypto / remote
        'apache', 'nginx', 'iis', 'tomcat', 'jetty',            # web servers
        'mysql', 'postgresql', 'sqlite', 'oracle', 'mssql',     # databases
        'mongodb', 'redis', 'elasticsearch',
        'office', 'word', 'excel', 'acrobat', 'reader',         # productivity
        'zoom', 'teams', 'slack', 'skype',                      # comms
        'git', 'docker', 'kubernetes', 'ansible', 'terraform',  # devops
        'wireshark', 'nmap', 'burp',                            # security tools
        'vlc', '7-zip', 'winrar',                               # common utilities
    ]

    def scan(self, target: str, progress_callback=None) -> list:
        if progress_callback:
            progress_callback(self.name, self.description, 'running', [])

        if sys.platform == 'win32':
            software = _get_windows_software()
        else:
            software = _get_linux_software()

        if not software:
            result = ScanResult(
                scanner=self.name,
                control_id='PATCH-003',
                status='NEEDS_REVIEW',
                severity='HIGH',
                evidence="Could not enumerate installed software. Manual review required.",
                confidence=0.1,
                remediation="Manually audit installed software for known CVEs using a vulnerability scanner.",
            )
            if progress_callback:
                progress_callback(self.name, self.description, 'done', [result])
            return [result]

        total = len(software)
        priority = [
            (name, ver) for name, ver in software
            if any(kw in name.lower() for kw in self.PRIORITY_KEYWORDS)
        ]

        findings = []
        checked = []
        all_cves = []

        for name, version in priority:
            keyword = f"{name} {version}".strip() if version else name
            short_keyword = name[:50]  # keep NVD query focused
            vulns = _nvd_query(short_keyword)
            if vulns:
                score, vector, top_cve_id = _highest_cvss(vulns)
                if score >= 7.0:
                    summary = _cve_summary(vulns)
                    findings.append({
                        'name': name, 'version': version,
                        'score': score, 'vector': vector,
                        'top_cve': top_cve_id, 'summary': summary,
                        'count': len(vulns),
                    })
                    all_cves.append(top_cve_id)
            checked.append(f"{name} {version}".strip())

        if findings:
            # Sort by CVSS score descending
            findings.sort(key=lambda f: f['score'], reverse=True)
            ev_lines = [
                f"Checked {len(checked)} of {total} installed packages against NVD.",
                f"{len(findings)} package(s) with CVEs (CVSS ≥7.0) found:\n",
            ]
            for f in findings:
                sev_tag = "CRITICAL" if f['score'] >= 9.0 else "HIGH"
                ev_lines.append(
                    f"[{sev_tag}] {f['name']} {f['version']}"
                    f" — top CVE: {f['top_cve']} (CVSS {f['score']:.1f})"
                )
                ev_lines.append(f"  {f['summary']}")

            max_score = findings[0]['score']
            severity = 'CRITICAL' if max_score >= 9.0 else 'HIGH'

            result = ScanResult(
                scanner=self.name,
                control_id='PATCH-003',
                status='NON_COMPLIANT',
                severity=severity,
                evidence='\n'.join(ev_lines),
                confidence=0.75,
                cvss_score=max_score,
                cvss_vector=findings[0].get('vector', ''),
                reachability='INDIRECT',
                remediation=(
                    f"Update the following vulnerable packages to patched versions:\n"
                    + '\n'.join(f"  - {f['name']} {f['version']} (CVE {f['top_cve']})" for f in findings)
                ),
            )
        else:
            if checked:
                ev = (
                    f"Checked {len(checked)} high-priority packages against NVD.\n"
                    f"No critical or high CVEs (CVSS ≥7.0) found in checked packages.\n"
                    f"Total installed packages: {total} (lower-priority packages not queried)."
                )
            else:
                ev = "No high-priority packages identified for CVE check."
            result = ScanResult(
                scanner=self.name,
                control_id='PATCH-003',
                status='COMPLIANT',
                severity='HIGH',
                evidence=ev,
                confidence=0.6,
            )

        if progress_callback:
            progress_callback(self.name, self.description, 'done', [result])

        return [result]


class ServicesScanner:
    """Checks for risky running services and unexpected listening ports."""
    name = "services"
    description = "Running services and listening ports"

    def scan(self, target: str, progress_callback=None) -> list:
        if progress_callback:
            progress_callback(self.name, self.description, 'running', [])

        results = []

        # ── SVCCONFIG-002: Risky / unnecessary services ──
        if sys.platform == 'win32':
            running = set(_get_running_services_windows())
            risky_map = _RISKY_SERVICES_WIN
        else:
            running = set(_get_running_services_linux())
            risky_map = _RISKY_SERVICES_LINUX

        found_risky = {svc: desc for svc, desc in risky_map.items() if svc in running}

        if found_risky:
            ev_lines = [
                f"Found {len(found_risky)} unnecessary or insecure service(s) running:\n"
            ]
            for svc, desc in found_risky.items():
                ev_lines.append(f"  [RUNNING] {svc} — {desc}")

            results.append(ScanResult(
                scanner=self.name,
                control_id='SVCCONFIG-002',
                status='NON_COMPLIANT',
                severity='HIGH',
                evidence='\n'.join(ev_lines),
                confidence=0.9,
                reachability='DIRECT',
                remediation=(
                    "Disable each unnecessary service:\n"
                    + ('\n'.join(
                        f"  Windows: sc config {svc} start=disabled && net stop {svc}"
                        if sys.platform == 'win32' else
                        f"  Linux: systemctl disable {svc} && systemctl stop {svc}"
                        for svc in found_risky
                    ))
                ),
            ))
        elif running:
            results.append(ScanResult(
                scanner=self.name,
                control_id='SVCCONFIG-002',
                status='COMPLIANT',
                severity='HIGH',
                evidence=(
                    f"No known insecure services (Telnet, FTP, TFTP, rsh, SNMP v1/v2) detected "
                    f"among {len(running)} running services."
                ),
                confidence=0.85,
            ))
        else:
            results.append(ScanResult(
                scanner=self.name,
                control_id='SVCCONFIG-002',
                status='NEEDS_REVIEW',
                severity='HIGH',
                evidence="Could not enumerate running services. Manual verification required.",
                confidence=0.2,
                remediation="Manually audit running services for unnecessary or insecure entries.",
            ))

        # ── SVCEXPOSE-001: Listening ports ──
        listening = _get_listening_ports()
        if listening:
            unique_ports = sorted(set(p for p, _, _, _ in listening))
            unexpected = [p for p in unique_ports if p not in _EXPECTED_PORTS]

            ev_lines = [f"Listening ports ({len(unique_ports)} total): {', '.join(str(p) for p in unique_ports)}\n"]

            if unexpected:
                ev_lines.append(f"Ports outside expected baseline ({len(unexpected)} flagged for review):")
                for p in unexpected:
                    ev_lines.append(f"  Port {p} — review process and business justification")
                status = 'NEEDS_REVIEW'
                sev = 'MEDIUM'
                remediation = (
                    "For each unexpected listening port:\n"
                    "  1. Identify the process/service bound to the port\n"
                    "  2. Determine if it is required for a business function\n"
                    "  3. If not required, stop the service and add a firewall rule to block it\n"
                    "  4. If required, document it in the authorized service list"
                )
            else:
                ev_lines.append("All listening ports are within the expected baseline.")
                status = 'COMPLIANT'
                sev = 'MEDIUM'
                remediation = ""

            results.append(ScanResult(
                scanner=self.name,
                control_id='SVCEXPOSE-001',
                status=status,
                severity=sev,
                evidence='\n'.join(ev_lines),
                confidence=0.8,
                remediation=remediation,
            ))
        else:
            results.append(ScanResult(
                scanner=self.name,
                control_id='SVCEXPOSE-001',
                status='NEEDS_REVIEW',
                severity='MEDIUM',
                evidence="Could not enumerate listening ports. Manual review required.",
                confidence=0.1,
                remediation="Run netstat -ano (Windows) or ss -tlnp (Linux) to audit listening ports.",
            ))

        if progress_callback:
            progress_callback(self.name, self.description, 'done', results)

        return results


# ── Public entry point ────────────────────────────────────────────────────────

def scan_os_target(target: str, progress_callback=None) -> list:
    """Run all OS scanners and return combined list of ScanResult objects.

    The `target` parameter is used as a label only — the scan always runs
    against the local machine.
    """
    all_results = []

    scanners = [
        OSVersionScanner(),
        SoftwareCVEScanner(),
        ServicesScanner(),
    ]

    for scanner in scanners:
        try:
            results = scanner.scan(target, progress_callback=progress_callback)
            all_results.extend(results)
        except Exception as e:
            # Never let a single scanner crash the whole assessment
            if progress_callback:
                progress_callback(scanner.name, f"Error: {e}", 'done', [])

    return all_results
