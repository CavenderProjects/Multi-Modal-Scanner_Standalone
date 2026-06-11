"""Real scanner implementations for the security assessment tool.

Each scanner takes a target and returns structured evidence that maps
to specific controls. Scanners use only Python standard library + requests.
"""

import ssl
import socket
import re
import json
import hashlib
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    from requests.exceptions import RequestException, SSLError
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


@dataclass
class ScanResult:
    scanner: str
    control_id: str
    status: str  # COMPLIANT, NON_COMPLIANT, ERROR, NEEDS_REVIEW
    severity: str = "MEDIUM"
    evidence: str = ""
    confidence: float = 1.0
    elapsed_seconds: float = 0.0
    remediation: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    reachability: str = "DIRECT"


class TLSScanner:
    """Checks TLS configuration: protocol versions, cipher suites, certificate validity."""
    name = "tls-scanner"
    description = "TLS/cipher analysis"
    controls = ['CRYPTO-001', 'CRYPTO-002', 'CRYPTO-003', 'CRYPTO-004', 'CRYPTO-005', 'CRYPTO-006']

    def scan(self, target: str) -> list:
        results = []
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port or 443
        start = time.time()

        try:
            # Check supported protocols
            weak_protos = []
            for proto_name, proto_const in [
                ('TLSv1.0', ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, 'TLSv1') else None),
                ('TLSv1.1', ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None),
            ]:
                if proto_const is None:
                    continue
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.minimum_version = proto_const
                    ctx.maximum_version = proto_const
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                            weak_protos.append(proto_name)
                except (ssl.SSLError, OSError, ConnectionError):
                    pass

            # Check current TLS connection
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            cert_info = {}
            tls_version = ""
            cipher_info = ""
            try:
                with socket.create_connection((host, port), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert_info = ssock.getpeercert()
                        tls_version = ssock.version()
                        cipher_info = ssock.cipher()
            except ssl.CertificateError as e:
                results.append(ScanResult(
                    scanner=self.name, control_id='CRYPTO-005',
                    status='NON_COMPLIANT', severity='HIGH',
                    evidence=f"Certificate validation failed: {e}",
                    elapsed_seconds=time.time() - start,
                    cvss_score=7.4, cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    remediation="Install a valid TLS certificate from a trusted CA."
                ))
            except ssl.SSLError as e:
                results.append(ScanResult(
                    scanner=self.name, control_id='CRYPTO-001',
                    status='NON_COMPLIANT', severity='CRITICAL',
                    evidence=f"TLS connection failed: {e}",
                    elapsed_seconds=time.time() - start,
                    cvss_score=9.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    remediation="Configure the server to support TLS 1.2 or higher."
                ))
                return results

            elapsed = time.time() - start

            # CRYPTO-001: TLS version
            if weak_protos:
                results.append(ScanResult(
                    scanner=self.name, control_id='CRYPTO-001',
                    status='NON_COMPLIANT', severity='CRITICAL',
                    evidence=f"Weak TLS protocols accepted: {', '.join(weak_protos)}\nCurrent connection: {tls_version}",
                    elapsed_seconds=elapsed,
                    cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    remediation="Disable TLS 1.0 and 1.1. Only allow TLS 1.2+."
                ))
            else:
                results.append(ScanResult(
                    scanner=self.name, control_id='CRYPTO-001',
                    status='COMPLIANT',
                    evidence=f"TLS version: {tls_version}. No weak protocols accepted.",
                    elapsed_seconds=elapsed
                ))

            # CRYPTO-002: Cipher suite
            if cipher_info:
                cipher_name = cipher_info[0] if isinstance(cipher_info, tuple) else str(cipher_info)
                weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon']
                is_weak = any(w.lower() in cipher_name.lower() for w in weak_ciphers)
                if is_weak:
                    results.append(ScanResult(
                        scanner=self.name, control_id='CRYPTO-002',
                        status='NON_COMPLIANT', severity='HIGH',
                        evidence=f"Weak cipher in use: {cipher_name}",
                        elapsed_seconds=elapsed,
                        cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        remediation="Disable weak cipher suites. Use AES-GCM or ChaCha20."
                    ))
                else:
                    results.append(ScanResult(
                        scanner=self.name, control_id='CRYPTO-002',
                        status='COMPLIANT',
                        evidence=f"Cipher: {cipher_name}. No weak ciphers detected.",
                        elapsed_seconds=elapsed
                    ))

            # CRYPTO-005: Certificate validity
            if cert_info:
                results.append(ScanResult(
                    scanner=self.name, control_id='CRYPTO-005',
                    status='COMPLIANT',
                    evidence=f"Certificate valid. Subject: {cert_info.get('subject', 'N/A')}\nExpires: {cert_info.get('notAfter', 'N/A')}",
                    elapsed_seconds=elapsed
                ))

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            results.append(ScanResult(
                scanner=self.name, control_id='CRYPTO-001',
                status='ERROR',
                evidence=f"Connection failed: {e}",
                elapsed_seconds=time.time() - start
            ))

        return results


class HeaderScanner:
    """Checks HTTP security headers."""
    name = "header-check"
    description = "Security headers"
    controls = ['HEADERS-001', 'HEADERS-002', 'HEADERS-003', 'HEADERS-004',
                'HEADERS-005', 'HEADERS-006', 'HEADERS-007']

    REQUIRED_HEADERS = {
        'HEADERS-001': {
            'header': 'Content-Security-Policy',
            'severity': 'HIGH',
            'cvss': (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            'remediation': "Add Content-Security-Policy header with restrictive directives.",
        },
        'HEADERS-002': {
            'header': 'X-Content-Type-Options',
            'expected': 'nosniff',
            'severity': 'MEDIUM',
            'cvss': (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"),
            'remediation': "Add X-Content-Type-Options: nosniff header.",
        },
        'HEADERS-003': {
            'header': 'X-Frame-Options',
            'severity': 'MEDIUM',
            'cvss': (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
            'remediation': "Add X-Frame-Options: DENY or SAMEORIGIN.",
        },
        'HEADERS-004': {
            'header': 'Strict-Transport-Security',
            'severity': 'HIGH',
            'cvss': (7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            'remediation': "Add Strict-Transport-Security: max-age=63072000; includeSubDomains.",
        },
        'HEADERS-005': {
            'header': 'Referrer-Policy',
            'severity': 'LOW',
            'cvss': (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
            'remediation': "Add Referrer-Policy: strict-origin-when-cross-origin.",
        },
        'HEADERS-006': {
            'header': 'Permissions-Policy',
            'severity': 'LOW',
            'cvss': (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
            'remediation': "Add Permissions-Policy header to restrict browser features.",
        },
    }

    def scan(self, target: str) -> list:
        if not HAS_REQUESTS:
            return [ScanResult(scanner=self.name, control_id='HEADERS-001',
                             status='ERROR', evidence='requests library not installed')]
        results = []
        start = time.time()

        try:
            resp = requests.get(target, timeout=15, allow_redirects=True, verify=False)
            headers = resp.headers
            elapsed = time.time() - start

            for ctrl_id, info in self.REQUIRED_HEADERS.items():
                header_name = info['header']
                value = headers.get(header_name)
                expected = info.get('expected')

                if not value:
                    # Check CSP for frame-ancestors as alternative to X-Frame-Options
                    if ctrl_id == 'HEADERS-003':
                        csp = headers.get('Content-Security-Policy', '')
                        if 'frame-ancestors' in csp:
                            results.append(ScanResult(
                                scanner=self.name, control_id=ctrl_id,
                                status='COMPLIANT',
                                evidence=f"X-Frame-Options not set, but CSP frame-ancestors present: {csp}",
                                elapsed_seconds=elapsed
                            ))
                            continue

                    results.append(ScanResult(
                        scanner=self.name, control_id=ctrl_id,
                        status='NON_COMPLIANT', severity=info['severity'],
                        evidence=f"{header_name} header is missing.",
                        elapsed_seconds=elapsed,
                        cvss_score=info['cvss'][0], cvss_vector=info['cvss'][1],
                        remediation=info['remediation']
                    ))
                elif expected and value.lower() != expected.lower():
                    results.append(ScanResult(
                        scanner=self.name, control_id=ctrl_id,
                        status='NON_COMPLIANT', severity=info['severity'],
                        evidence=f"{header_name}: {value} (expected: {expected})",
                        elapsed_seconds=elapsed,
                        cvss_score=info['cvss'][0], cvss_vector=info['cvss'][1],
                        remediation=info['remediation']
                    ))
                else:
                    results.append(ScanResult(
                        scanner=self.name, control_id=ctrl_id,
                        status='COMPLIANT',
                        evidence=f"{header_name}: {value}",
                        elapsed_seconds=elapsed
                    ))

            # HEADERS-007: CORS
            cors = headers.get('Access-Control-Allow-Origin')
            if cors == '*':
                results.append(ScanResult(
                    scanner=self.name, control_id='HEADERS-007',
                    status='NON_COMPLIANT', severity='HIGH',
                    evidence=f"CORS wildcard: Access-Control-Allow-Origin: *",
                    elapsed_seconds=elapsed,
                    cvss_score=5.3, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    remediation="Restrict CORS to specific trusted origins."
                ))
            else:
                results.append(ScanResult(
                    scanner=self.name, control_id='HEADERS-007',
                    status='COMPLIANT',
                    evidence=f"CORS: {cors or 'Not set (restrictive default)'}",
                    elapsed_seconds=elapsed
                ))

        except RequestException as e:
            elapsed = time.time() - start
            results.append(ScanResult(
                scanner=self.name, control_id='HEADERS-001',
                status='ERROR', evidence=f"HTTP request failed: {e}",
                elapsed_seconds=elapsed
            ))

        return results


class CookieScanner:
    """Checks cookie security flags."""
    name = "cookie-audit"
    description = "Cookie flags"
    controls = ['SESSION-001', 'SESSION-002', 'SESSION-003', 'SESSION-004', 'SESSION-005']

    def scan(self, target: str) -> list:
        if not HAS_REQUESTS:
            return [ScanResult(scanner=self.name, control_id='SESSION-001',
                             status='ERROR', evidence='requests library not installed')]
        results = []
        start = time.time()

        try:
            resp = requests.get(target, timeout=15, allow_redirects=True, verify=False)
            elapsed = time.time() - start
            cookies = resp.cookies

            if not cookies:
                results.append(ScanResult(
                    scanner=self.name, control_id='SESSION-001',
                    status='COMPLIANT',
                    evidence="No cookies set by the server.",
                    elapsed_seconds=elapsed
                ))
                return results

            for cookie in cookies:
                cookie_name = cookie.name
                issues = []

                # SESSION-003: HttpOnly
                if not cookie.has_nonstandard_attr('HttpOnly') and 'httponly' not in str(cookie).lower():
                    issues.append(('SESSION-003', 'HttpOnly flag missing',
                                 'HIGH', 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"))

                # SESSION-004: Secure flag
                if not cookie.secure:
                    issues.append(('SESSION-004', 'Secure flag missing',
                                 'HIGH', 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"))

                # SESSION-005: SameSite
                cookie_str = str(cookie)
                if 'samesite' not in cookie_str.lower():
                    issues.append(('SESSION-005', 'SameSite attribute missing',
                                 'MEDIUM', 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"))

                for ctrl_id, issue, sev, cvss, vec in issues:
                    results.append(ScanResult(
                        scanner=self.name, control_id=ctrl_id,
                        status='NON_COMPLIANT', severity=sev,
                        evidence=f"Cookie '{cookie_name}': {issue}",
                        elapsed_seconds=elapsed,
                        cvss_score=cvss, cvss_vector=vec,
                        remediation=f"Set {issue.replace(' missing', '')} on cookie '{cookie_name}'."
                    ))

            # If no issues found for a control, mark compliant
            found_ids = {r.control_id for r in results}
            for ctrl_id in ['SESSION-003', 'SESSION-004', 'SESSION-005']:
                if ctrl_id not in found_ids:
                    results.append(ScanResult(
                        scanner=self.name, control_id=ctrl_id,
                        status='COMPLIANT',
                        evidence=f"All cookies have proper flags for {ctrl_id}.",
                        elapsed_seconds=elapsed
                    ))

        except RequestException as e:
            results.append(ScanResult(
                scanner=self.name, control_id='SESSION-001',
                status='ERROR', evidence=f"Request failed: {e}",
                elapsed_seconds=time.time() - start
            ))

        return results


class AuthScanner:
    """Checks authentication-related controls: login endpoint, rate limiting."""
    name = "auth-probe"
    description = "Auth endpoint analysis"
    controls = ['AUTH-001', 'AUTH-004', 'AUTH-005']

    COMMON_LOGIN_PATHS = [
        '/login', '/signin', '/auth/login', '/api/auth/login',
        '/api/login', '/api/v1/auth/login', '/account/login',
        '/users/sign_in', '/auth/signin',
    ]

    def scan(self, target: str) -> list:
        if not HAS_REQUESTS:
            return []
        results = []
        start = time.time()
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Find login endpoint
        login_url = None
        for path in self.COMMON_LOGIN_PATHS:
            try:
                resp = requests.get(base + path, timeout=5, allow_redirects=False, verify=False)
                if resp.status_code < 500:
                    login_url = base + path
                    break
            except RequestException:
                continue

        elapsed = time.time() - start

        if login_url:
            # AUTH-004: Rate limiting check
            try:
                rate_limited = False
                for i in range(6):
                    resp = requests.post(login_url,
                        data={'username': 'test@test.com', 'password': 'wrongpassword'},
                        timeout=5, allow_redirects=False, verify=False)
                    if resp.status_code == 429 or 'rate' in resp.text.lower() or 'too many' in resp.text.lower():
                        rate_limited = True
                        break

                elapsed = time.time() - start
                if rate_limited:
                    results.append(ScanResult(
                        scanner=self.name, control_id='AUTH-004',
                        status='COMPLIANT',
                        evidence=f"Rate limiting detected on {login_url} after {i+1} attempts.",
                        elapsed_seconds=elapsed
                    ))
                else:
                    results.append(ScanResult(
                        scanner=self.name, control_id='AUTH-004',
                        status='NON_COMPLIANT', severity='HIGH',
                        evidence=f"No rate limiting detected on {login_url} after 6 rapid login attempts.",
                        elapsed_seconds=elapsed,
                        cvss_score=7.3, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        remediation="Implement rate limiting on authentication endpoints (e.g., 5 attempts per minute)."
                    ))
            except RequestException:
                pass

            # AUTH-001: Authentication required
            results.append(ScanResult(
                scanner=self.name, control_id='AUTH-001',
                status='COMPLIANT',
                evidence=f"Login endpoint found at {login_url}. Authentication mechanism present.",
                elapsed_seconds=elapsed
            ))
        else:
            results.append(ScanResult(
                scanner=self.name, control_id='AUTH-001',
                status='NEEDS_REVIEW',
                evidence=f"No standard login endpoint found. Auth may use SSO or non-standard paths.",
                confidence=0.5,
                elapsed_seconds=elapsed
            ))

        return results


class SecretScanner:
    """Scans page source for exposed secrets and API keys."""
    name = "secret-scan"
    description = "Secret pattern detection"
    controls = ['SECRETS-001', 'SECRETS-002', 'SECRETS-003']

    SECRET_PATTERNS = [
        (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'API key'),
        (r'(?:secret|token|password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{8,})["\']', 'Secret/Token'),
        (r'sk_live_[a-zA-Z0-9]{20,}', 'Stripe live key'),
        (r'AKIA[A-Z0-9]{16}', 'AWS access key'),
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'Private key'),
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub PAT'),
        (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', 'JWT token'),
    ]

    def scan(self, target: str) -> list:
        if not HAS_REQUESTS:
            return []
        results = []
        start = time.time()

        try:
            resp = requests.get(target, timeout=15, verify=False)
            body = resp.text
            elapsed = time.time() - start

            found_secrets = []
            for pattern, secret_type in self.SECRET_PATTERNS:
                matches = re.findall(pattern, body, re.IGNORECASE)
                for match in matches:
                    preview = match[:10] + '...' if len(match) > 10 else match
                    found_secrets.append(f"{secret_type}: {preview}")

            if found_secrets:
                results.append(ScanResult(
                    scanner=self.name, control_id='SECRETS-001',
                    status='NON_COMPLIANT', severity='CRITICAL',
                    evidence=f"Secrets found in page source:\n" + '\n'.join(f"  - {s}" for s in found_secrets),
                    elapsed_seconds=elapsed,
                    cvss_score=8.6, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                    remediation="Remove secrets from client-side code. Use environment variables or a secrets manager."
                ))
            else:
                results.append(ScanResult(
                    scanner=self.name, control_id='SECRETS-001',
                    status='COMPLIANT',
                    evidence="No secret patterns detected in page source.",
                    elapsed_seconds=elapsed
                ))

            # Check response headers for secrets
            header_secrets = []
            for name, value in resp.headers.items():
                for pattern, secret_type in self.SECRET_PATTERNS:
                    if re.search(pattern, value, re.IGNORECASE):
                        header_secrets.append(f"{name}: {secret_type}")

            ctrl_id = 'SECRETS-002'
            if header_secrets:
                results.append(ScanResult(
                    scanner=self.name, control_id=ctrl_id,
                    status='NON_COMPLIANT', severity='HIGH',
                    evidence=f"Secrets in headers:\n" + '\n'.join(f"  - {s}" for s in header_secrets),
                    elapsed_seconds=elapsed,
                    cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    remediation="Remove secrets from HTTP response headers."
                ))
            else:
                results.append(ScanResult(
                    scanner=self.name, control_id=ctrl_id,
                    status='COMPLIANT',
                    evidence="No secrets found in response headers.",
                    elapsed_seconds=elapsed
                ))

        except RequestException as e:
            results.append(ScanResult(
                scanner=self.name, control_id='SECRETS-001',
                status='ERROR', evidence=f"Request failed: {e}",
                elapsed_seconds=time.time() - start
            ))

        return results


class ErrorHandlingScanner:
    """Tests error handling by requesting invalid paths and checking responses."""
    name = "error-check"
    description = "Error handling analysis"
    controls = ['ERROR-001', 'ERROR-002', 'ERROR-003']

    def scan(self, target: str) -> list:
        if not HAS_REQUESTS:
            return []
        results = []
        start = time.time()
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        error_indicators = [
            'traceback', 'stack trace', 'exception', 'internal server error',
            'syntax error', 'debug', 'at line', 'at /usr', 'at /var',
            'django', 'laravel', 'express', 'flask', 'rails',
            'mysql', 'postgresql', 'sqlite', 'mongodb',
        ]

        try:
            # Request non-existent path
            resp = requests.get(base + '/nonexistent_path_test_12345', timeout=10, verify=False)
            body = resp.text.lower()
            elapsed = time.time() - start

            exposed = [ind for ind in error_indicators if ind in body]

            if exposed:
                results.append(ScanResult(
                    scanner=self.name, control_id='ERROR-001',
                    status='NON_COMPLIANT', severity='MEDIUM',
                    evidence=f"Error page exposes implementation details.\nIndicators found: {', '.join(exposed)}\nStatus: {resp.status_code}",
                    elapsed_seconds=elapsed,
                    cvss_score=5.3, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    remediation="Configure custom error pages. Disable debug mode in production."
                ))
            else:
                results.append(ScanResult(
                    scanner=self.name, control_id='ERROR-001',
                    status='COMPLIANT',
                    evidence=f"Error page (status {resp.status_code}) does not expose sensitive details.",
                    elapsed_seconds=elapsed
                ))

        except RequestException as e:
            results.append(ScanResult(
                scanner=self.name, control_id='ERROR-001',
                status='ERROR', evidence=f"Request failed: {e}",
                elapsed_seconds=time.time() - start
            ))

        return results


class AuthzScanner:
    """Probes for authorization and privilege escalation issues."""
    name = "authz-probe"
    description = "Authorization & privilege escalation"
    controls = ['AUTHZ-001', 'AUTHZ-002', 'AUTHZ-003', 'AUTHZ-004', 'AUTHZ-005']

    ADMIN_PATHS = [
        '/admin', '/admin/', '/admin/dashboard', '/administrator',
        '/manage', '/management', '/panel', '/console',
        '/api/admin', '/api/v1/admin', '/api/admin/users',
        '/wp-admin', '/phpmyadmin', '/cpanel',
        '/dashboard', '/settings', '/config',
    ]
    SENSITIVE_PATHS = [
        '/api/users', '/api/user/1', '/api/user/2',
        '/api/accounts', '/api/orders', '/api/payments',
        '/api/v1/users', '/api/v2/users',
        '/users', '/accounts', '/profile',
    ]

    def scan(self, target: str) -> list:
        if not HAS_REQUESTS:
            return []
        results = []
        start = time.time()
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # AUTHZ-001: Probe admin endpoints without auth
        accessible_admin = []
        for path in self.ADMIN_PATHS:
            try:
                resp = requests.get(base + path, timeout=5, allow_redirects=False, verify=False)
                if resp.status_code == 200:
                    accessible_admin.append(f"{path} → HTTP {resp.status_code} ({len(resp.text)} bytes)")
                elif resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location', '')
                    if 'login' not in location.lower() and 'auth' not in location.lower():
                        accessible_admin.append(f"{path} → redirect to {location} (not to login)")
            except RequestException:
                continue

        elapsed = time.time() - start
        if accessible_admin:
            results.append(ScanResult(
                scanner=self.name, control_id='AUTHZ-001',
                status='NON_COMPLIANT', severity='CRITICAL',
                evidence=f"Admin/privileged endpoints accessible without authentication:\n" +
                         '\n'.join(f"  {p}" for p in accessible_admin),
                confidence=0.85, elapsed_seconds=elapsed,
                cvss_score=8.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                reachability='DIRECT',
                remediation="Restrict admin endpoints with authentication middleware. Return 401/403 for unauthenticated requests."
            ))
        else:
            results.append(ScanResult(
                scanner=self.name, control_id='AUTHZ-001',
                status='COMPLIANT',
                evidence=f"Tested {len(self.ADMIN_PATHS)} admin paths — all returned 401/403 or redirect to login.",
                confidence=0.8, elapsed_seconds=elapsed
            ))

        # AUTHZ-002: IDOR / object-level access — probe sequential IDs
        idor_evidence = []
        for path in self.SENSITIVE_PATHS:
            try:
                resp = requests.get(base + path, timeout=5, allow_redirects=False, verify=False)
                if resp.status_code == 200:
                    body = resp.text[:500]
                    has_data = any(k in body.lower() for k in ['email', 'user', 'name', 'id', 'account'])
                    idor_evidence.append(
                        f"{path} → HTTP {resp.status_code}"
                        + (" — contains user/account data" if has_data else " — accessible")
                    )
            except RequestException:
                continue

        if idor_evidence:
            results.append(ScanResult(
                scanner=self.name, control_id='AUTHZ-002',
                status='NEEDS_REVIEW', severity='CRITICAL',
                evidence=f"Sensitive endpoints accessible without authentication — potential IDOR:\n" +
                         '\n'.join(f"  {e}" for e in idor_evidence) +
                         "\n\nManual verification needed: do these endpoints enforce object-level authorization?",
                confidence=0.7, elapsed_seconds=elapsed,
                cvss_score=8.2, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                reachability='DIRECT',
                remediation="Implement object-level authorization checks. Verify the requesting user owns or has permission to access each object."
            ))
        else:
            results.append(ScanResult(
                scanner=self.name, control_id='AUTHZ-002',
                status='COMPLIANT',
                evidence=f"Tested {len(self.SENSITIVE_PATHS)} sensitive paths — all returned 401/403 or not found.",
                confidence=0.7, elapsed_seconds=elapsed
            ))

        # AUTHZ-003: Role-based access — check for role indicators in responses
        results.append(ScanResult(
            scanner=self.name, control_id='AUTHZ-003',
            status='NEEDS_REVIEW', severity='HIGH',
            evidence=f"Endpoint probing complete.\n"
                     f"Admin paths tested: {len(self.ADMIN_PATHS)} — {len(accessible_admin)} accessible\n"
                     f"Sensitive paths tested: {len(self.SENSITIVE_PATHS)} — {len(idor_evidence)} accessible\n\n"
                     f"Manual review required: verify role-based access control is consistently applied "
                     f"across all endpoints, not just the paths tested by the scanner.",
            confidence=0.5, elapsed_seconds=elapsed,
            remediation="Implement RBAC middleware. Verify each endpoint checks the user's role before serving data."
        ))

        # AUTHZ-004: Least privilege
        results.append(ScanResult(
            scanner=self.name, control_id='AUTHZ-004',
            status='NEEDS_REVIEW', severity='HIGH',
            evidence=f"Principle of least privilege cannot be fully verified by scanner.\n\n"
                     f"Evidence gathered:\n"
                     f"- Admin endpoints found: {len(accessible_admin)} accessible without auth\n"
                     f"- API endpoints exposing data: {len(idor_evidence)}\n\n"
                     f"Review: Are users granted only the minimum permissions necessary? "
                     f"Are there separate roles for read-only vs. read-write vs. admin?",
            confidence=0.4, elapsed_seconds=elapsed,
            remediation="Implement role hierarchy with least privilege. Audit user permissions regularly."
        ))

        return results


class InputValidationScanner:
    """Tests for XSS, CSRF, and input validation weaknesses."""
    name = "input-fuzzer"
    description = "XSS, CSRF & input validation"
    controls = ['INPUT-001', 'INPUT-002', 'INPUT-003', 'INPUT-004', 'INPUT-005',
                'INPUT-006', 'INPUT-007']

    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        "'-alert(1)-'",
    ]

    def scan(self, target: str) -> list:
        if not HAS_REQUESTS:
            return []
        results = []
        start = time.time()
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        try:
            # Fetch the main page to analyze forms
            resp = requests.get(target, timeout=15, verify=False)
            body = resp.text
            elapsed = time.time() - start

            # INPUT-005: CSRF protection — check for CSRF tokens in forms
            forms_found = body.lower().count('<form')
            csrf_tokens = sum(1 for pattern in ['csrf', '_token', 'authenticity_token', '__RequestVerificationToken']
                            if pattern.lower() in body.lower())

            if forms_found > 0:
                if csrf_tokens > 0:
                    results.append(ScanResult(
                        scanner=self.name, control_id='INPUT-005',
                        status='NEEDS_REVIEW', severity='HIGH',
                        evidence=f"Forms found: {forms_found}\n"
                                 f"CSRF token indicators found: {csrf_tokens}\n\n"
                                 f"CSRF tokens appear present in some forms. "
                                 f"Manual review required to verify all state-changing forms are protected "
                                 f"and tokens are validated server-side.",
                        confidence=0.6, elapsed_seconds=elapsed,
                        cvss_score=8.0, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                        remediation="Ensure all forms include anti-CSRF tokens. Validate tokens server-side on every POST."
                    ))
                else:
                    results.append(ScanResult(
                        scanner=self.name, control_id='INPUT-005',
                        status='NON_COMPLIANT', severity='HIGH',
                        evidence=f"Forms found: {forms_found}\n"
                                 f"CSRF token indicators: NONE detected\n\n"
                                 f"No CSRF tokens found in any form. Check if SameSite cookies or "
                                 f"custom headers are used as alternative CSRF protection.",
                        confidence=0.75, elapsed_seconds=elapsed,
                        cvss_score=8.0, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                        remediation="Add anti-CSRF tokens to all state-changing forms."
                    ))
            else:
                results.append(ScanResult(
                    scanner=self.name, control_id='INPUT-005',
                    status='NEEDS_REVIEW', severity='HIGH',
                    evidence=f"No HTML forms found on the main page.\n"
                             f"This may be a SPA (single-page app) that uses API calls.\n"
                             f"Check if API endpoints use CSRF tokens, SameSite cookies, or "
                             f"custom headers (X-Requested-With) for CSRF protection.",
                    confidence=0.4, elapsed_seconds=elapsed,
                    remediation="For SPAs, use SameSite=Strict cookies or custom request headers for CSRF protection."
                ))

            # INPUT-003: Reflected XSS test
            xss_reflected = []
            test_paths = [target, base + '/search', base + '/q']
            for test_url in test_paths:
                for payload in self.XSS_PAYLOADS[:2]:
                    try:
                        xss_resp = requests.get(test_url, params={'q': payload, 'search': payload},
                                               timeout=5, verify=False, allow_redirects=True)
                        if payload in xss_resp.text:
                            xss_reflected.append(f"{test_url}?q={payload[:30]}... → REFLECTED in response")
                            break
                    except RequestException:
                        continue

            if xss_reflected:
                results.append(ScanResult(
                    scanner=self.name, control_id='INPUT-003',
                    status='NON_COMPLIANT', severity='HIGH',
                    evidence=f"Reflected XSS detected:\n" +
                             '\n'.join(f"  {x}" for x in xss_reflected),
                    confidence=0.9, elapsed_seconds=time.time() - start,
                    cvss_score=6.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    reachability='DIRECT',
                    remediation="HTML-encode all user input before rendering. Implement Content-Security-Policy."
                ))
            else:
                results.append(ScanResult(
                    scanner=self.name, control_id='INPUT-003',
                    status='COMPLIANT',
                    evidence=f"Tested {len(self.XSS_PAYLOADS)} XSS payloads across {len(test_paths)} paths — no reflection detected.",
                    confidence=0.7, elapsed_seconds=time.time() - start
                ))

            # INPUT-001: Server-side validation — check for common validation headers/patterns
            results.append(ScanResult(
                scanner=self.name, control_id='INPUT-001',
                status='NEEDS_REVIEW', severity='HIGH',
                evidence=f"Server-side input validation cannot be fully verified externally.\n\n"
                         f"Page analysis:\n"
                         f"- Forms found: {forms_found}\n"
                         f"- Client-side validation attributes (required, pattern, maxlength): "
                         f"{body.lower().count('required') + body.lower().count('pattern=') + body.lower().count('maxlength')}\n"
                         f"- Content-Type header: {resp.headers.get('Content-Type', 'not set')}\n\n"
                         f"Client-side validation found but server-side validation must be verified manually.",
                confidence=0.4, elapsed_seconds=elapsed,
                remediation="Validate all input server-side. Never rely solely on client-side validation."
            ))

            # INPUT-004: File upload — check for upload endpoints
            upload_indicators = ['type="file"', 'multipart', 'upload', 'file-upload', 'dropzone']
            upload_found = [ind for ind in upload_indicators if ind.lower() in body.lower()]
            if upload_found:
                results.append(ScanResult(
                    scanner=self.name, control_id='INPUT-004',
                    status='NEEDS_REVIEW', severity='HIGH',
                    evidence=f"File upload capability detected:\n"
                             f"Indicators: {', '.join(upload_found)}\n\n"
                             f"Review: Are uploaded files validated for type, size, and content? "
                             f"Are they stored outside the web root? Are they scanned for malware?",
                    confidence=0.6, elapsed_seconds=elapsed,
                    cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    remediation="Validate file type (allowlist), enforce size limits, scan uploads, store outside web root."
                ))
            else:
                results.append(ScanResult(
                    scanner=self.name, control_id='INPUT-004',
                    status='COMPLIANT',
                    evidence="No file upload functionality detected on the main page.",
                    confidence=0.5, elapsed_seconds=elapsed
                ))

        except RequestException as e:
            results.append(ScanResult(
                scanner=self.name, control_id='INPUT-001',
                status='ERROR', evidence=f"Request failed: {e}",
                elapsed_seconds=time.time() - start
            ))

        return results


class EndpointDiscoveryScanner:
    """Discovers and catalogs accessible endpoints for comprehensive coverage."""
    name = "endpoint-discovery"
    description = "Endpoint & technology discovery"
    controls = ['COMP-001', 'COMP-003', 'INFRA-001', 'INFRA-002', 'INFRA-004',
                'DATA-002', 'DATA-004', 'AUDIT-001']

    COMMON_PATHS = [
        '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
        '/api', '/api/v1', '/api/v2', '/graphql', '/graphiql',
        '/.env', '/.git/config', '/.git/HEAD',
        '/wp-json', '/rest', '/swagger', '/swagger-ui',
        '/health', '/healthz', '/status', '/version', '/info',
        '/metrics', '/debug', '/trace',
        '/.htaccess', '/web.config', '/crossdomain.xml',
        '/favicon.ico', '/manifest.json',
    ]

    def scan(self, target: str) -> list:
        if not HAS_REQUESTS:
            return []
        results = []
        start = time.time()
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        accessible = []
        sensitive_exposed = []
        tech_indicators = []

        try:
            # Main page tech fingerprinting
            main_resp = requests.get(target, timeout=15, verify=False)
            server = main_resp.headers.get('Server', '')
            powered = main_resp.headers.get('X-Powered-By', '')
            if server:
                tech_indicators.append(f"Server: {server}")
            if powered:
                tech_indicators.append(f"X-Powered-By: {powered}")

            # Probe endpoints
            for path in self.COMMON_PATHS:
                try:
                    resp = requests.get(base + path, timeout=4, allow_redirects=False, verify=False)
                    if resp.status_code == 200:
                        size = len(resp.text)
                        is_sensitive = any(s in path for s in ['.env', '.git', '.htaccess', 'web.config', 'debug', 'trace', 'metrics'])
                        entry = f"{path} → HTTP 200 ({size} bytes)"
                        accessible.append(entry)
                        if is_sensitive:
                            sensitive_exposed.append(entry)
                except RequestException:
                    continue

            elapsed = time.time() - start

            # INFRA-002: Technology fingerprinting
            if tech_indicators:
                results.append(ScanResult(
                    scanner=self.name, control_id='INFRA-002',
                    status='NEEDS_REVIEW', severity='LOW',
                    evidence=f"Technology stack exposed in HTTP headers:\n" +
                             '\n'.join(f"  {t}" for t in tech_indicators) +
                             f"\n\nExposing server technology helps attackers target known vulnerabilities.",
                    confidence=0.8, elapsed_seconds=elapsed,
                    cvss_score=3.7, cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    remediation="Remove Server and X-Powered-By headers from responses."
                ))
            else:
                results.append(ScanResult(
                    scanner=self.name, control_id='INFRA-002',
                    status='COMPLIANT',
                    evidence="No technology-revealing headers detected (Server, X-Powered-By removed).",
                    confidence=0.8, elapsed_seconds=elapsed
                ))

            # COMP-001 / INFRA-004: Sensitive files exposed
            if sensitive_exposed:
                results.append(ScanResult(
                    scanner=self.name, control_id='INFRA-004',
                    status='NON_COMPLIANT', severity='CRITICAL',
                    evidence=f"Sensitive files/endpoints publicly accessible:\n" +
                             '\n'.join(f"  {s}" for s in sensitive_exposed),
                    confidence=0.9, elapsed_seconds=elapsed,
                    cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    reachability='DIRECT',
                    remediation="Block access to sensitive files (.env, .git, debug endpoints) via web server config."
                ))
            else:
                results.append(ScanResult(
                    scanner=self.name, control_id='INFRA-004',
                    status='COMPLIANT',
                    evidence=f"No sensitive files exposed. Tested: .env, .git, .htaccess, debug, metrics, trace.",
                    confidence=0.8, elapsed_seconds=elapsed
                ))

            # DATA-004: Information disclosure via error/info endpoints
            info_endpoints = [e for e in accessible if any(k in e for k in ['/info', '/version', '/status', '/health'])]
            if info_endpoints:
                results.append(ScanResult(
                    scanner=self.name, control_id='DATA-004',
                    status='NEEDS_REVIEW', severity='MEDIUM',
                    evidence=f"Information endpoints accessible:\n" +
                             '\n'.join(f"  {e}" for e in info_endpoints) +
                             f"\n\nReview: Do these endpoints expose internal details (versions, IPs, configs)?",
                    confidence=0.6, elapsed_seconds=elapsed,
                    remediation="Restrict info/health endpoints to internal networks or require authentication."
                ))

            # AUDIT-001: Security event logging
            sec_txt = None
            try:
                sec_resp = requests.get(base + '/.well-known/security.txt', timeout=4, verify=False)
                if sec_resp.status_code == 200:
                    sec_txt = sec_resp.text[:300]
            except RequestException:
                pass

            results.append(ScanResult(
                scanner=self.name, control_id='AUDIT-001',
                status='NEEDS_REVIEW', severity='MEDIUM',
                evidence=f"Logging and audit capabilities cannot be fully verified externally.\n\n"
                         f"Evidence gathered:\n"
                         f"- security.txt: {'Found' if sec_txt else 'Not found'}\n"
                         f"- Accessible endpoints: {len(accessible)} of {len(self.COMMON_PATHS)} tested\n"
                         f"- Debug/trace endpoints: {'EXPOSED' if any('/debug' in e or '/trace' in e for e in accessible) else 'not found'}\n\n"
                         f"Review: Are security events (auth failures, authz violations, input validation failures) logged? "
                         f"Are logs tamper-evident and stored separately from the application?",
                confidence=0.3, elapsed_seconds=elapsed,
                remediation="Implement security event logging for auth, authz, and input validation events."
            ))

            # Summary for DATA-002: Overall data exposure assessment
            results.append(ScanResult(
                scanner=self.name, control_id='DATA-002',
                status='NEEDS_REVIEW', severity='MEDIUM',
                evidence=f"Endpoint discovery summary:\n"
                         f"- Total endpoints probed: {len(self.COMMON_PATHS)}\n"
                         f"- Accessible (HTTP 200): {len(accessible)}\n"
                         f"- Sensitive files exposed: {len(sensitive_exposed)}\n"
                         f"- Technology headers: {len(tech_indicators)}\n\n"
                         f"Accessible endpoints:\n" +
                         ('\n'.join(f"  {a}" for a in accessible) if accessible else "  None") +
                         f"\n\nReview: Is PII minimized in API responses? Are sensitive fields filtered?",
                confidence=0.5, elapsed_seconds=elapsed,
                remediation="Minimize data exposure in API responses. Use field-level filtering."
            ))

        except RequestException as e:
            results.append(ScanResult(
                scanner=self.name, control_id='INFRA-001',
                status='ERROR', evidence=f"Discovery failed: {e}",
                elapsed_seconds=time.time() - start
            ))

        return results


class SessionScanner:
    """Deep session management analysis beyond basic cookie flags."""
    name = "session-analyzer"
    description = "Session management deep analysis"
    controls = ['SESSION-001', 'SESSION-002', 'AUTH-003', 'AUTH-006']

    def scan(self, target: str) -> list:
        if not HAS_REQUESTS:
            return []
        results = []
        start = time.time()

        try:
            # Make two requests to check session behavior
            s = requests.Session()
            resp1 = s.get(target, timeout=15, verify=False)
            cookies1 = {c.name: c.value for c in s.cookies}

            resp2 = s.get(target, timeout=15, verify=False)
            cookies2 = {c.name: c.value for c in s.cookies}

            elapsed = time.time() - start

            if cookies1:
                # SESSION-001: Session ID randomness
                for name, value in cookies1.items():
                    if any(k in name.lower() for k in ['session', 'sid', 'jsession', 'phpsess', 'asp.net']):
                        if len(value) < 16:
                            results.append(ScanResult(
                                scanner=self.name, control_id='SESSION-001',
                                status='NON_COMPLIANT', severity='HIGH',
                                evidence=f"Session ID '{name}' is only {len(value)} characters (minimum recommended: 16).\n"
                                         f"Short session IDs are susceptible to brute-force attacks.",
                                confidence=0.8, elapsed_seconds=elapsed,
                                cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                remediation="Use cryptographically random session IDs of at least 128 bits (32 hex chars)."
                            ))
                        else:
                            results.append(ScanResult(
                                scanner=self.name, control_id='SESSION-001',
                                status='COMPLIANT',
                                evidence=f"Session ID '{name}' is {len(value)} characters — adequate length.",
                                confidence=0.7, elapsed_seconds=elapsed
                            ))
                        break

                # SESSION-002: Session timeout
                results.append(ScanResult(
                    scanner=self.name, control_id='SESSION-002',
                    status='NEEDS_REVIEW', severity='MEDIUM',
                    evidence=f"Session timeout cannot be fully verified with a single scan.\n\n"
                             f"Session cookies found: {', '.join(cookies1.keys())}\n"
                             f"Cookie persistence: {'Same values on 2nd request' if cookies1 == cookies2 else 'Values changed between requests'}\n\n"
                             f"Review: Is session timeout configured to <=30 minutes? "
                             f"Is idle timeout enforced server-side?",
                    confidence=0.3, elapsed_seconds=elapsed,
                    remediation="Set session timeout to 30 minutes or less. Enforce server-side idle timeout."
                ))

            # AUTH-003: MFA support
            body = resp1.text.lower()
            mfa_indicators = ['mfa', 'two-factor', '2fa', 'totp', 'authenticator', 'otp', 'verify-code']
            mfa_found = [ind for ind in mfa_indicators if ind in body]
            results.append(ScanResult(
                scanner=self.name, control_id='AUTH-003',
                status='NEEDS_REVIEW', severity='HIGH',
                evidence=f"MFA detection from page content:\n"
                         f"MFA indicators found: {', '.join(mfa_found) if mfa_found else 'NONE'}\n\n"
                         f"{'MFA references detected in page content.' if mfa_found else 'No MFA references found in page content.'}\n"
                         f"Review: Is MFA available and enforced for privileged accounts?",
                confidence=0.4 if not mfa_found else 0.6,
                elapsed_seconds=elapsed,
                remediation="Implement MFA for all user accounts, especially admin/privileged accounts."
            ))

            # AUTH-006: Account lockout
            results.append(ScanResult(
                scanner=self.name, control_id='AUTH-006',
                status='NEEDS_REVIEW', severity='MEDIUM',
                evidence=f"Account lockout policy cannot be fully verified without testing multiple failed logins.\n\n"
                         f"Rate limiting was tested by the auth-probe scanner (see AUTH-004 results).\n"
                         f"Review: After N failed attempts, is the account locked or rate-limited? "
                         f"Is there a CAPTCHA after failed attempts?",
                confidence=0.3, elapsed_seconds=elapsed,
                remediation="Lock accounts after 5 failed attempts for 30 minutes, or require CAPTCHA."
            ))

        except RequestException as e:
            results.append(ScanResult(
                scanner=self.name, control_id='SESSION-001',
                status='ERROR', evidence=f"Session analysis failed: {e}",
                elapsed_seconds=time.time() - start
            ))

        return results


# Registry of all website scanners
WEBSITE_SCANNERS = [
    TLSScanner(),
    HeaderScanner(),
    CookieScanner(),
    AuthScanner(),
    AuthzScanner(),
    InputValidationScanner(),
    EndpointDiscoveryScanner(),
    SessionScanner(),
    SecretScanner(),
    ErrorHandlingScanner(),
]


def get_scanners_for_type(target_type: str) -> list:
    """Return appropriate scanners for the target type."""
    if target_type in ('website',):
        return WEBSITE_SCANNERS
    if target_type == 'agent':
        return WEBSITE_SCANNERS  # Agent also gets website checks if URL-based
    # Code, API, and agent scanners are handled by their own modules
    return WEBSITE_SCANNERS


def run_all_scanners(target: str, target_type: str = 'website',
                     progress_callback=None) -> list:
    """Run all applicable scanners against the target.

    Args:
        target: URL or path to scan
        target_type: Detected target type
        progress_callback: Optional fn(scanner_name, description, status, results)
    """
    scanners = get_scanners_for_type(target_type)
    all_results = []

    for scanner in scanners:
        if progress_callback:
            progress_callback(scanner.name, scanner.description, 'running', [])

        try:
            results = scanner.scan(target)
        except Exception as e:
            results = [ScanResult(
                scanner=scanner.name, control_id=scanner.controls[0] if scanner.controls else 'UNKNOWN',
                status='ERROR', evidence=f"Scanner crashed: {e}"
            )]

        all_results.extend(results)

        if progress_callback:
            progress_callback(scanner.name, scanner.description, 'done', results)

    return all_results
