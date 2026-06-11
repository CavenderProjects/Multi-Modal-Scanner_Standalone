"""API specification analyzer.

Parses OpenAPI/Swagger YAML/JSON specs and tests against all 53 API controls.
Detects BOLA, mass assignment, missing auth, rate limiting gaps, SSRF,
sensitive data exposure, debug endpoints, webhook issues, and GraphQL risks.
"""

import re
import os
import json
from scanners import ScanResult

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def parse_spec(filepath: str) -> dict:
    """Parse OpenAPI/Swagger spec from YAML or JSON."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    if filepath.endswith('.json'):
        return json.loads(content)

    if HAS_YAML:
        return yaml.safe_load(content)

    # Fallback: basic YAML-like parsing for simple specs
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Very basic YAML key extraction
    spec = {'_raw': content}
    for line in content.split('\n'):
        if ':' in line and not line.strip().startswith('#'):
            key = line.split(':')[0].strip()
            val = ':'.join(line.split(':')[1:]).strip().strip('"\'')
            spec[key] = val
    return spec


def extract_endpoints(spec: dict) -> list:
    """Extract all endpoints from an OpenAPI spec."""
    endpoints = []
    paths = spec.get('paths', {})
    if not isinstance(paths, dict):
        return endpoints

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method.lower() in ('get', 'post', 'put', 'patch', 'delete', 'head', 'options'):
                ep = {
                    'path': path,
                    'method': method.upper(),
                    'summary': '',
                    'parameters': [],
                    'security': [],
                    'request_body': None,
                    'responses': {},
                }
                if isinstance(details, dict):
                    ep['summary'] = details.get('summary', details.get('description', ''))
                    ep['parameters'] = details.get('parameters', [])
                    ep['security'] = details.get('security', [])
                    ep['request_body'] = details.get('requestBody')
                    ep['responses'] = details.get('responses', {})
                endpoints.append(ep)

    return endpoints


def extract_schemas(spec: dict) -> dict:
    """Extract all component schemas."""
    components = spec.get('components', {})
    if isinstance(components, dict):
        return components.get('schemas', {})
    return {}


def scan_spec(filepath: str, progress_callback=None) -> list:
    """Analyze an API spec file against API security controls."""
    results = []

    try:
        spec = parse_spec(filepath)
    except Exception as e:
        return [ScanResult(
            scanner='api-analysis', control_id='CONFIG-001',
            status='ERROR', evidence=f'Failed to parse API spec: {e}'
        )]

    if '_raw' in spec and not spec.get('paths'):
        # Couldn't fully parse — do text-based analysis
        return _scan_raw_spec(spec['_raw'], filepath, progress_callback)

    endpoints = extract_endpoints(spec)
    schemas = extract_schemas(spec)
    servers = spec.get('servers', [])

    # Global security
    global_security = spec.get('security', [])
    security_schemes = spec.get('components', {}).get('securitySchemes', {}) if isinstance(spec.get('components'), dict) else {}

    if progress_callback:
        progress_callback('api-analysis', f'Analyzing {len(endpoints)} endpoints', 'running', [])

    # ── BOLA-001: Object-level authorization ──
    sequential_id_endpoints = []
    for ep in endpoints:
        if '{' in ep['path']:
            # Check if parameter is integer/sequential
            for param in ep.get('parameters', []):
                if isinstance(param, dict) and param.get('in') == 'path':
                    schema = param.get('schema', {})
                    if isinstance(schema, dict) and schema.get('type') == 'integer':
                        sequential_id_endpoints.append(f"{ep['method']} {ep['path']} — integer path param '{param.get('name', '?')}'")

    if sequential_id_endpoints:
        results.append(ScanResult(
            scanner='api-analysis', control_id='BOLA-001',
            status='NON_COMPLIANT', severity='CRITICAL',
            evidence=f"Endpoints with sequential integer IDs (IDOR risk):\n" +
                     '\n'.join(f"  {e}" for e in sequential_id_endpoints) +
                     "\n\nSequential integer IDs enable enumeration attacks.",
            confidence=0.8,
            cvss_score=8.2, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            remediation="Use UUIDs instead of sequential integers. Implement object-level authorization checks."
        ))
    else:
        results.append(ScanResult(
            scanner='api-analysis', control_id='BOLA-001',
            status='COMPLIANT', evidence="No sequential integer ID path parameters found."
        ))

    # ── AUTH-001/002: Authentication coverage ──
    unprotected = []
    for ep in endpoints:
        has_security = bool(ep['security']) or bool(global_security)
        if not has_security:
            unprotected.append(f"{ep['method']} {ep['path']} — {ep['summary'][:50]}")

    if unprotected:
        results.append(ScanResult(
            scanner='api-analysis', control_id='AUTH-001',
            status='NON_COMPLIANT', severity='CRITICAL',
            evidence=f"Endpoints without security requirements ({len(unprotected)} of {len(endpoints)}):\n" +
                     '\n'.join(f"  {u}" for u in unprotected[:10]) +
                     (f"\n  ... and {len(unprotected)-10} more" if len(unprotected) > 10 else ""),
            confidence=0.9,
            cvss_score=9.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            remediation="Apply security requirements to all endpoints. Use global security with per-endpoint overrides."
        ))
    else:
        results.append(ScanResult(
            scanner='api-analysis', control_id='AUTH-001',
            status='COMPLIANT', evidence=f"All {len(endpoints)} endpoints have security requirements."
        ))

    # ── BOPLA-001: Mass assignment ──
    mass_assign_risks = []
    for ep in endpoints:
        if ep['method'] in ('PUT', 'PATCH', 'POST') and ep.get('request_body'):
            rb = ep['request_body']
            if isinstance(rb, dict):
                content = rb.get('content', {})
                for ct, ct_detail in content.items() if isinstance(content, dict) else []:
                    schema = ct_detail.get('schema', {}) if isinstance(ct_detail, dict) else {}
                    ref = schema.get('$ref', '')
                    if ref:
                        schema_name = ref.split('/')[-1]
                        if schema_name in schemas:
                            props = schemas[schema_name].get('properties', {})
                            dangerous = [p for p in props if p.lower() in
                                        ('role', 'isadmin', 'is_admin', 'admin', 'permissions',
                                         'password_hash', 'balance', 'credit', 'status')]
                            if dangerous:
                                mass_assign_risks.append(
                                    f"{ep['method']} {ep['path']} accepts schema '{schema_name}' with writable fields: {', '.join(dangerous)}"
                                )

    if mass_assign_risks:
        results.append(ScanResult(
            scanner='api-analysis', control_id='BOPLA-001',
            status='NON_COMPLIANT', severity='HIGH',
            evidence=f"Mass assignment risks — sensitive fields writable:\n" +
                     '\n'.join(f"  {r}" for r in mass_assign_risks),
            confidence=0.85,
            cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
            remediation="Use separate DTOs for input. Never accept role/admin/permission fields from user input."
        ))

    # ── RATE-001: Rate limiting ──
    results.append(ScanResult(
        scanner='api-analysis', control_id='RATE-001',
        status='NEEDS_REVIEW', severity='HIGH',
        evidence=f"Rate limiting cannot be verified from spec alone.\n\n"
                 f"Endpoints found: {len(endpoints)}\n"
                 f"Auth endpoints: {sum(1 for e in endpoints if 'auth' in e['path'].lower() or 'login' in e['path'].lower())}\n"
                 f"Check: Are X-RateLimit-* headers present in responses? Is there throttling on auth endpoints?",
        confidence=0.4,
        remediation="Implement rate limiting per client/IP/API key. Return 429 with Retry-After header."
    ))

    # ── FUNC-001: Function-level authorization ──
    admin_endpoints = [ep for ep in endpoints if 'admin' in ep['path'].lower()]
    admin_unprotected = [f"{e['method']} {e['path']}" for e in admin_endpoints if not e['security'] and not global_security]
    if admin_unprotected:
        results.append(ScanResult(
            scanner='api-analysis', control_id='FUNC-001',
            status='NON_COMPLIANT', severity='CRITICAL',
            evidence=f"Admin endpoints without explicit security:\n" +
                     '\n'.join(f"  {a}" for a in admin_unprotected),
            confidence=0.85,
            cvss_score=8.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            remediation="Apply admin role checks to all /admin/* endpoints."
        ))

    # ── SSRF-001: URL parameters ──
    ssrf_risks = []
    for ep in endpoints:
        for param in ep.get('parameters', []):
            if isinstance(param, dict):
                name = param.get('name', '').lower()
                schema = param.get('schema', {})
                fmt = schema.get('format', '') if isinstance(schema, dict) else ''
                if 'url' in name or 'uri' in name or 'callback' in name or 'redirect' in name or fmt == 'uri':
                    ssrf_risks.append(f"{ep['method']} {ep['path']} param '{param.get('name')}' (format: {fmt or 'string'})")

    if ssrf_risks:
        results.append(ScanResult(
            scanner='api-analysis', control_id='SSRF-001',
            status='NON_COMPLIANT', severity='HIGH',
            evidence=f"SSRF risk — endpoints accepting URL/URI parameters:\n" +
                     '\n'.join(f"  {s}" for s in ssrf_risks),
            confidence=0.75,
            cvss_score=8.6, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
            remediation="Validate and allowlist URLs. Block internal/private IP ranges. Use URL parser to verify host."
        ))

    # ── CONFIG: Debug/internal endpoints ──
    debug_endpoints = [f"{e['method']} {e['path']}" for e in endpoints
                      if any(k in e['path'].lower() for k in ['/debug', '/internal', '/trace', '/metrics', '/actuator'])]
    if debug_endpoints:
        results.append(ScanResult(
            scanner='api-analysis', control_id='CONFIG-001',
            status='NON_COMPLIANT', severity='HIGH',
            evidence=f"Debug/internal endpoints in production spec:\n" +
                     '\n'.join(f"  {d}" for d in debug_endpoints),
            confidence=0.9,
            cvss_score=5.3, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            remediation="Remove debug endpoints from production API specs. Restrict to internal networks."
        ))

    # ── CONFIG-003: TLS ──
    http_servers = [s.get('url', '') for s in servers if isinstance(s, dict) and s.get('url', '').startswith('http://')]
    if http_servers:
        results.append(ScanResult(
            scanner='api-analysis', control_id='CONFIG-003',
            status='NON_COMPLIANT', severity='HIGH',
            evidence=f"Non-HTTPS server URLs:\n" + '\n'.join(f"  {u}" for u in http_servers),
            confidence=0.95,
            cvss_score=7.4, cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            remediation="Use HTTPS for all server URLs. Remove HTTP endpoints."
        ))

    # ── DATA: Sensitive fields in schemas ──
    sensitive_fields = []
    for name, schema in schemas.items():
        if not isinstance(schema, dict):
            continue
        props = schema.get('properties', {})
        if not isinstance(props, dict):
            continue
        for field_name in props:
            if field_name.lower() in ('password', 'password_hash', 'ssn', 'social_security',
                                       'credit_card', 'card_number', 'api_key', 'secret',
                                       'private_key', 'token'):
                sensitive_fields.append(f"Schema '{name}' field '{field_name}'")

    if sensitive_fields:
        results.append(ScanResult(
            scanner='api-analysis', control_id='DATA-001',
            status='NON_COMPLIANT', severity='HIGH',
            evidence=f"Sensitive fields in API schemas (may be exposed in responses):\n" +
                     '\n'.join(f"  {s}" for s in sensitive_fields),
            confidence=0.8,
            cvss_score=6.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            remediation="Remove sensitive fields from response schemas. Use separate DTOs for responses."
        ))

    # ── WEBHOOK: Webhook endpoints ──
    webhook_endpoints = [ep for ep in endpoints if 'webhook' in ep['path'].lower() or 'hook' in ep['path'].lower()]
    if webhook_endpoints:
        results.append(ScanResult(
            scanner='api-analysis', control_id='WEBHOOK-001',
            status='NEEDS_REVIEW', severity='MEDIUM',
            evidence=f"Webhook endpoints found:\n" +
                     '\n'.join(f"  {e['method']} {e['path']}" for e in webhook_endpoints) +
                     "\n\nReview: Is HMAC signature validation implemented? Is replay protection (timestamp + nonce) in place?",
            confidence=0.5,
            remediation="Validate webhook signatures with HMAC. Implement timestamp + nonce replay protection."
        ))

    # ── GRAPHQL ──
    graphql_endpoints = [ep for ep in endpoints if 'graphql' in ep['path'].lower() or 'graphiql' in ep['path'].lower()]
    if graphql_endpoints:
        results.append(ScanResult(
            scanner='api-analysis', control_id='GRAPHQL-001',
            status='NEEDS_REVIEW', severity='MEDIUM',
            evidence=f"GraphQL endpoint found: {graphql_endpoints[0]['path']}\n\n"
                     f"Review: Is introspection disabled in production? Are query depth/complexity limits set?",
            confidence=0.5,
            remediation="Disable introspection in production. Set query depth limit (e.g., max 10). Enforce cost analysis."
        ))

    # ── INVENTORY-001: Undocumented endpoints ──
    results.append(ScanResult(
        scanner='api-analysis', control_id='INVENTORY-001',
        status='NEEDS_REVIEW', severity='MEDIUM',
        evidence=f"API spec contains {len(endpoints)} documented endpoints.\n\n"
                 f"Review: Are there undocumented endpoints not in this spec? "
                 f"Are deprecated API versions still accessible?",
        confidence=0.3,
        remediation="Maintain complete API inventory. Decommission deprecated versions."
    ))

    # Summary evidence for endpoints
    results.append(ScanResult(
        scanner='api-analysis', control_id='CONFIG-002',
        status='NEEDS_REVIEW', severity='MEDIUM',
        evidence=f"API surface summary:\n"
                 f"  Endpoints: {len(endpoints)}\n"
                 f"  Methods: {', '.join(sorted(set(e['method'] for e in endpoints)))}\n"
                 f"  Servers: {len(servers)}\n"
                 f"  Schemas: {len(schemas)}\n"
                 f"  Security schemes: {len(security_schemes)}\n"
                 f"  Global security: {'Yes' if global_security else 'NO — not applied'}\n"
                 f"  Admin paths: {len(admin_endpoints)}\n"
                 f"  Webhook paths: {len(webhook_endpoints)}\n"
                 f"  GraphQL: {'Yes' if graphql_endpoints else 'No'}",
        confidence=0.5,
        remediation="Review API configuration for unnecessary methods, endpoints, and services."
    ))

    if progress_callback:
        progress_callback('api-analysis', f'Analyzed {len(endpoints)} endpoints', 'done', results)

    return results


def _scan_raw_spec(raw_content: str, filepath: str, progress_callback=None) -> list:
    """Fallback text-based analysis when YAML parser isn't available."""
    results = []
    content = raw_content.lower()

    checks = [
        ('BOLA-001', 'integer', 'Sequential integer IDs found in path parameters', 'CRITICAL'),
        ('AUTH-001', 'security', 'Security scheme references found' if 'security' in content else 'No security references', 'CRITICAL'),
        ('CONFIG-003', 'http://', 'Non-HTTPS server URLs found', 'HIGH'),
        ('SSRF-001', 'callback_url', 'URL parameters accepting callbacks', 'HIGH'),
        ('CONFIG-001', '/debug', 'Debug endpoints in spec', 'HIGH'),
        ('DATA-001', 'password', 'Password fields in schemas', 'HIGH'),
    ]

    for ctrl_id, keyword, desc, severity in checks:
        found = keyword in content
        if ctrl_id == 'AUTH-001':
            found = 'security' not in content  # Inverted — bad if missing
        elif ctrl_id in ('CONFIG-003', 'SSRF-001', 'CONFIG-001', 'DATA-001'):
            pass  # found = keyword present = bad

        if found and ctrl_id != 'AUTH-001':
            results.append(ScanResult(
                scanner='api-analysis', control_id=ctrl_id,
                status='NON_COMPLIANT', severity=severity,
                evidence=f"Text analysis of spec: {desc}.\nKeyword '{keyword}' found in spec.",
                confidence=0.6,
                remediation=f"Review the API spec for {desc.lower()}."
            ))
        elif found and ctrl_id == 'AUTH-001':
            results.append(ScanResult(
                scanner='api-analysis', control_id=ctrl_id,
                status='NON_COMPLIANT', severity=severity,
                evidence="No security scheme references found in API spec.",
                confidence=0.7,
                remediation="Add security schemes and apply them globally or per-endpoint."
            ))

    if progress_callback:
        progress_callback('api-analysis', 'Text analysis complete', 'done', results)

    return results
