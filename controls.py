"""Controls library parser.

Reads all Markdown control libraries and STIG imports, parses them into
structured Control objects, and classifies each control into tiers:
- automatic_confirmation: Scanner can determine pass/fail with no user input
- review_required: Scanner collects evidence but user confirms the judgment
- manual_confirmation: No scanner can help; user answers from knowledge/docs
"""

import re
import os
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


@dataclass
class Control:
    control_id: str
    name: str
    family: str
    library: str  # website_agent, api, code_review, interconnected, stig
    cia: str = ""
    severity: str = "MEDIUM"
    statement: str = ""
    test_procedure: str = ""
    review_procedure: str = ""   # test + all language-specific sub-fields
    fix_text: str = ""
    tier: str = "review_required"  # automatic_confirmation | review_required | manual_confirmation
    frameworks: list = field(default_factory=list)
    cwe: str = ""
    languages: str = "ALL"
    sources: str = ""
    # STIG-specific
    vuln_id: str = ""
    rule_id: str = ""
    srg_ref: str = ""
    ccis: list = field(default_factory=list)
    check_content: str = ""


# Controls that can be fully determined by scanners
AUTO_FAMILIES = {
    # Website/agent
    'CRYPTO', 'HEADERS', 'SESSION',
    # API
    'CONFIG', 'RATE',
    # Code
    'CPX-STRUCT', 'CPX-METRIC', 'CPX-MAINTAIN',
    'DEV-DEP', 'DEV-BUILD', 'DEV-QUAL',
}

AUTO_IDS = {
    'AUTH-001', 'AUTH-002', 'AUTH-005', 'AUTH-006',
    'INPUT-001', 'INPUT-002', 'INPUT-003', 'INPUT-004',
    'SECRETS-001', 'SECRETS-002', 'SECRETS-003',
    'ERROR-001', 'ERROR-002', 'ERROR-003',
    'DATA-004',
    'COMP-001', 'COMP-003',
    'INFRA-001', 'INFRA-002', 'INFRA-003', 'INFRA-004',
    # API
    'BOLA-001', 'AUTH-001', 'AUTH-002', 'AUTH-003',
    'BOPLA-001', 'FUNC-001',
    'SSRF-001', 'CONFIG-001', 'CONFIG-002', 'CONFIG-003', 'CONFIG-004',
    'INPUT-001', 'INPUT-002', 'INPUT-003',
    'DATA-001', 'DATA-002', 'DATA-003',
    'SECRETS-001', 'SECRETS-002',
    'GRAPHQL-001', 'GRAPHQL-002', 'GRAPHQL-003',
    'WEBHOOK-001', 'WEBHOOK-002',
    # OS/Software
    'PATCH-001', 'PATCH-003', 'EOL-001', 'SVCCONFIG-002', 'SVCEXPOSE-001',
    # Code
    'SEC-INJ-001', 'SEC-INJ-002', 'SEC-INJ-003', 'SEC-INJ-004',
    'SEC-INJ-005', 'SEC-INJ-006',
    'SEC-MEM-001', 'SEC-MEM-002', 'SEC-MEM-003', 'SEC-MEM-004',
    'SEC-MEM-005', 'SEC-MEM-006',
    'SEC-CRYPTO-001', 'SEC-CRYPTO-002', 'SEC-CRYPTO-003', 'SEC-CRYPTO-004',
    'SEC-DATA-001', 'SEC-DATA-003', 'SEC-DATA-004',
    'DEV-BUILD-001', 'DEV-BUILD-002',
}

MANUAL_IDS = {
    'AUTHZ-005', 'DATA-003', 'DATA-001', 'AUDIT-002', 'AUDIT-003',
    'COMP-002', 'AGENT-007', 'AGENT-010',
    # Cross-system
    'TRUST-001', 'TRUST-002', 'TRUST-003',
    'INCIDENT-001', 'INCIDENT-002',
    'SUPPLY-001', 'SUPPLY-002',
    # Code
    'DEV-QUAL-003',
    'DEV-TEST-002', 'DEV-TEST-003',
    'SEC-AUTH-001', 'SEC-AUTH-002',
    # OS/Software
    'PATCH-002', 'SOFTINV-001',
}


def classify_control(control_id: str, family: str) -> str:
    if control_id in AUTO_IDS or family in AUTO_FAMILIES:
        return "automatic_confirmation"
    if control_id in MANUAL_IDS:
        return "manual_confirmation"
    return "review_required"


def get_references_dir():
    standalone_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(standalone_dir), "references")


CONTROL_LIBRARIES = {
    "website_agent": {
        "file": "controls-library.md",
        "label": "Website & AI agent controls",
        "count": 67,
    },
    "api": {
        "file": "api-controls-library.md",
        "label": "API vulnerability controls",
        "count": 53,
    },
    "code_review": {
        "file": "code-review-controls.md",
        "label": "Source code review controls",
        "count": 51,
    },
    "interconnected": {
        "file": "interconnected-controls.md",
        "label": "Interconnected systems controls",
        "count": 27,
    },
    "os_software": {
        "file": "os-software-controls.md",
        "label": "OS & software vulnerability controls",
        "count": 12,
    },
}


def parse_controls_library(library_key: str) -> list:
    """Parse a Markdown controls library into Control objects."""
    lib_info = CONTROL_LIBRARIES.get(library_key)
    if not lib_info:
        return []

    refs_dir = get_references_dir()
    filepath = os.path.join(refs_dir, lib_info["file"])
    if not os.path.exists(filepath):
        return []

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    controls = []
    # Split on control ID headers (### XXXX-NNN or ### SEC-XXX-NNN)
    sections = re.split(r'\n### ', content)

    for section in sections[1:]:  # skip preamble
        ctrl = _parse_control_section(section, library_key)
        if ctrl:
            controls.append(ctrl)

    return controls


def _parse_control_section(section: str, library_key: str) -> Optional[Control]:
    """Parse a single control section from Markdown."""
    lines = section.strip().split('\n')
    if not lines:
        return None

    header = lines[0].strip()

    # Extract control ID from header — must look like a real control ID
    # Valid: AUTH-001, SEC-INJ-003, AGENT-011, HEADERS-007, CPX-METRIC-001
    # Invalid: OWASP, Framework, Platform, Legend, Overview
    ctrl_id_match = re.match(r'^([A-Z]{2,10}(?:-[A-Z]{2,10})?-\d{3,4})\b', header)
    if not ctrl_id_match:
        # Also accept V-NNNNNN format (STIG Vuln IDs)
        ctrl_id_match = re.match(r'^(V-\d{5,6})\b', header)
        if not ctrl_id_match:
            return None

    ctrl_id = ctrl_id_match.group(1)

    # Skip known non-control sections that might slip through
    skip_prefixes = ('NOTE', 'TODO', 'LEGEND', 'TOTAL', 'TABLE')
    if ctrl_id.startswith(skip_prefixes):
        return None

    fields = {}
    current_key = None
    for line in lines[1:]:
        field_match = re.match(r'^- \*\*(.+?)\*\*:\s*(.*)', line)
        if field_match:
            current_key = field_match.group(1).lower().strip()
            fields[current_key] = field_match.group(2).strip()
        elif current_key and line.startswith('  '):
            fields[current_key] = fields.get(current_key, '') + '\n' + line.strip()

    # Must have at least a name or statement to be a real control
    name = fields.get('name', fields.get('control name', ''))
    if not name and not fields.get('statement', '') and not fields.get('control statement', ''):
        return None

    if not name:
        name = header

    family = fields.get('family', _infer_family(ctrl_id))
    cia = fields.get('cia', '')
    severity = fields.get('severity if non-compliant', fields.get('severity', fields.get('mapped severity', 'MEDIUM')))
    statement = fields.get('statement', fields.get('control statement', ''))
    test_proc = fields.get('test', fields.get('test approach', fields.get('check', '')))
    cwe = fields.get('cwe', '')
    languages = fields.get('languages', 'ALL')
    sources = fields.get('sources', '')

    # Build review_procedure: general test description + all language-specific sub-fields
    _known = {
        'name', 'control name', 'languages', 'cia', 'sources', 'cwe', 'statement',
        'control statement', 'severity', 'severity if non-compliant', 'mapped severity',
        'family', 'test', 'test approach', 'check', 'tier', 'source', 'reachability',
        'framework', 'fix', 'fix text', 'check content', 'description', 'rationale',
        'references', 'rule id', 'group id', 'version', 'weight', 'legacy ids',
        'discussion', 'vul discuss', 'ia controls', 'responsibility', 'priority',
        'security override guidance', 'potential impact', 'third party tools',
        'mitigation control', 'severity override guidance', 'title', 'id', 'mitigations',
        'applicable platforms', 'notes', 'common consequences', 'observed examples',
    }
    review_parts = []
    if test_proc:
        review_parts.append(test_proc)
    for k, v in fields.items():
        if k not in _known and v:
            review_parts.append(f"{k.title()}: {v}")
    review_proc = '\n'.join(review_parts)

    tier = classify_control(ctrl_id, family)

    return Control(
        control_id=ctrl_id,
        name=name,
        family=family,
        library=library_key,
        cia=cia,
        severity=severity.upper() if severity else 'MEDIUM',
        statement=statement,
        test_procedure=test_proc,
        review_procedure=review_proc,
        tier=tier,
        cwe=cwe,
        languages=languages,
        sources=sources,
    )


def _infer_family(control_id: str) -> str:
    parts = control_id.rsplit('-', 1)
    return parts[0] if len(parts) > 1 else control_id


def parse_stig_controls(md_path: str) -> list:
    """Parse a STIG controls library (generated by stig_parser.py) into Control objects."""
    if not os.path.exists(md_path):
        return []

    with open(md_path, 'r', encoding='utf-8') as f:
        content = f.read()

    controls = []
    sections = re.split(r'\n### ', content)

    for section in sections[1:]:
        lines = section.strip().split('\n')
        if not lines:
            continue

        fields = {}
        for line in lines:
            field_match = re.match(r'^- \*\*(.+?)\*\*:\s*(.*)', line)
            if field_match:
                key = field_match.group(1).lower().strip()
                fields[key] = field_match.group(2).strip()

        ctrl_id = fields.get('control id', fields.get('version', ''))
        if not ctrl_id:
            continue

        vuln_id = fields.get('vuln id', '')
        severity = fields.get('mapped severity', 'MEDIUM')
        cia = fields.get('cia', 'C, I')

        ctrl = Control(
            control_id=ctrl_id,
            name=fields.get('name', ''),
            family='STIG',
            library='stig',
            cia=cia,
            severity=severity,
            statement=fields.get('statement', ''),
            test_procedure=fields.get('check', ''),
            fix_text=fields.get('fix', ''),
            tier='review_required',
            vuln_id=vuln_id,
            rule_id=fields.get('rule id', ''),
            srg_ref=fields.get('srg', ''),
            ccis=fields.get('ccis', '').split(', ') if fields.get('ccis') else [],
            check_content=fields.get('check', ''),
        )
        controls.append(ctrl)

    return controls


def load_all_controls(selected_sets: list, stig_paths: list = None) -> list:
    """Load controls from selected control sets and STIG imports."""
    all_controls = []

    for lib_key in selected_sets:
        if lib_key in CONTROL_LIBRARIES:
            controls = parse_controls_library(lib_key)
            all_controls.extend(controls)

    if stig_paths:
        for path in stig_paths:
            controls = parse_stig_controls(path)
            all_controls.extend(controls)

    return all_controls


def get_tier_counts(controls: list) -> dict:
    counts = {"automatic_confirmation": 0, "review_required": 0, "manual_confirmation": 0}
    for c in controls:
        if c.tier in counts:
            counts[c.tier] += 1
    return counts
