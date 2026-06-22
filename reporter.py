"""Report generator — produces HTML, Markdown, CSV, and JSON reports.

Uses the existing report-template.html as the base for HTML reports,
injecting assessment data as a JavaScript CONTROLS array.
"""

import json
import csv
import io
import os
from datetime import datetime
from pathlib import Path
from detector import extract_hostname


def _parse_controls_from_html(content: str):
    """Extract the controls list from an HTML report string. Returns list or None."""
    # ── New template format: data in a JSON script tag ──
    tag_open = '<script type="application/json" id="sat-controls-data">'
    tag_close = '</script>'
    tag_idx = content.find(tag_open)
    if tag_idx != -1:
        json_start = tag_idx + len(tag_open)
        json_end = content.find(tag_close, json_start)
        if json_end != -1:
            raw = content[json_start:json_end].strip()
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    return parsed
            except (json.JSONDecodeError, ValueError):
                pass

    # ── Old template format: inline JS variable (const or var) ──
    for marker in ('const CONTROLS = ', 'var CONTROLS = '):
        idx = content.find(marker)
        if idx != -1:
            idx += len(marker)
            while idx < len(content) and content[idx] in ' \t\n\r':
                idx += 1
            try:
                decoder = json.JSONDecoder()
                parsed, _ = decoder.raw_decode(content, idx)
                if isinstance(parsed, list):
                    return parsed
            except (json.JSONDecodeError, ValueError):
                pass

    return None


def extract_prior_data_from_report(html_path: str) -> dict:
    """Parse a previously saved HTML report and return carryover data.

    Returns a dict keyed by control ID:
        {
            '<control_id>': {
                'is_fp':         bool,
                'justification': str,   # only when is_fp is True
                'note':          str,   # only when a note was recorded
            },
            ...
        }
    Returns an empty dict on any error.
    """
    try:
        with open(html_path, 'r', encoding='utf-8') as f:
            content = f.read()

        controls = _parse_controls_from_html(content)
        if not controls:
            return {}

        result = {}
        for c in controls:
            if not isinstance(c, dict) or not c.get('id'):
                continue
            # Handle both non-STIG field names (mitigation/mitigationDesc/note)
            # and STIG field names (isFalsePositive/fpJustification/userNotes/stigStatus)
            is_fp       = c.get('mitigation') == 'YES' or bool(c.get('isFalsePositive'))
            just        = (c.get('mitigationDesc') or c.get('fpJustification', '')).strip()
            note        = (c.get('note') or c.get('userNotes', '')).strip()
            stig_status = c.get('stigStatus', '').strip()
            if is_fp or note or stig_status:
                result[c['id']] = {
                    'is_fp':         is_fp,
                    'justification': just if is_fp else '',
                    'note':          note,
                    'stig_status':   stig_status,
                }
        return result
    except Exception:
        return {}


def extract_fps_from_report(html_path: str) -> set:
    """Legacy wrapper — returns only the set of FP control IDs.

    Prefer extract_prior_data_from_report for new callers.
    """
    data = extract_prior_data_from_report(html_path)
    return {cid for cid, v in data.items() if v['is_fp']}


def get_template_path(target_type: str = None, selected_sets: list = None):
    """Return the correct HTML template path for the given assessment type."""
    standalone_dir = os.path.dirname(os.path.abspath(__file__))
    assets_dir = os.path.dirname(standalone_dir)

    # Determine which template to use based on what was assessed.
    # selected_sets takes priority; target_type is a fallback.
    sets = set(selected_sets or [])

    if 'interconnected' in sets or target_type == 'interconnected':
        name = 'interconnected-report-template.html'
    elif 'code_review' in sets or target_type in ('code', 'code_review'):
        name = 'code-review-report-template.html'
    elif 'api' in sets or target_type == 'api':
        name = 'api-report-template.html'
    elif 'os_software' in sets or target_type == 'os':
        name = 'report-template.html'
    elif 'website_agent' in sets or target_type == 'agent':
        name = 'agent-report-template.html'
    else:
        name = 'report-template.html'

    return os.path.join(assets_dir, "assets", name)


def _report_title(target_type: str = None, selected_sets: list = None) -> str:
    """Return a human-readable report title for the assessment type."""
    sets = set(selected_sets or [])
    if 'interconnected' in sets or target_type == 'interconnected':
        return 'Interconnected Systems Security Assessment'
    if 'code_review' in sets or target_type in ('code', 'code_review'):
        return 'Code Review Security Assessment'
    if 'api' in sets or target_type == 'api':
        return 'API Security Assessment'
    if target_type == 'agent':
        return 'Agent Security Assessment'
    if 'os_software' in sets or target_type == 'os':
        return 'OS & Software Security Assessment'
    return 'Website Security Assessment'


def get_stig_template_path():
    standalone_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(standalone_dir), "assets", "stig-report-template.html")


def _sev_to_cat(severity: str) -> str:
    """Map pen-tester severity back to STIG CAT level.

    Reverses the SEVERITY_MAP in stig_parser.py:
      stig high   -> CRITICAL -> CAT I
      stig medium -> HIGH     -> CAT II
      stig low    -> MEDIUM   -> CAT III
    """
    s = (severity or "").upper()
    if s == "CRITICAL":
        return "CAT I"
    if s == "HIGH":
        return "CAT II"
    if s in ("MEDIUM", "LOW"):
        return "CAT III"
    return "CAT II"


def generate_html_report(engine, output_path: str) -> str:
    """Generate interactive HTML dashboard report."""
    # Route STIG assessments to the STIG-specific template
    stig_controls = [r for r in engine.all_results if r.control.library == 'stig']
    if stig_controls:
        return _generate_stig_html_report(engine, output_path)

    summary = engine.get_summary()
    findings_data = []

    for r in engine.all_results:
        finding = {
            "id": r.control.control_id,
            "name": r.control.name,
            "family": r.control.family,
            "status": r.status,
            "severity": r.severity or r.control.severity,
            "cia": r.control.cia,
            "evidence": r.evidence or "",
            "finding": r.evidence or "",
            "remediation": r.remediation or r.control.fix_text or "",
            "isFalsePositive": r.is_false_positive,
            "fpJustification": r.fp_justification or "",
            "userNotes": getattr(r, 'user_notes', '') or "",
            "tier": r.tier,
            "statement": r.control.statement or "",
            "review_steps": r.control.review_procedure or r.control.test_procedure or "",
            "reachability": r.reachability or "DIRECT",
            "cvss": {
                "score": r.cvss_score,
                "vector": r.cvss_vector
            } if r.cvss_score else None,
            "frameworks": r.control.frameworks if r.control.frameworks else [],
            "source": r.scanner_name or "manual",
        }
        findings_data.append(finding)

    # Build standalone HTML
    template_path = get_template_path(engine.target_type,
                                      getattr(engine, 'selected_sets', None))
    if os.path.exists(template_path):
        with open(template_path, 'r', encoding='utf-8') as f:
            template = f.read()

        non_compliant = [f for f in findings_data if f['status'] == 'NON_COMPLIANT']
        sev = lambda s: sum(1 for f in non_compliant if f['severity'] == s)
        title = _report_title(engine.target_type, getattr(engine, 'selected_sets', None))

        # Clean display name: strip protocol from URLs, use basename for paths
        raw_target = engine.target
        if raw_target.startswith(('http://', 'https://')):
            display_target = extract_hostname(raw_target)
        else:
            display_target = os.path.basename(raw_target.rstrip('/\\')) or raw_target

        substitutions = {
            '{{REPORT_TITLE}}':        title,
            '{{TARGET_NAME}}':         display_target,
            '{{TOTAL_CONTROLS}}':      str(summary['total']),
            '{{FRAMEWORK}}':           engine.framework_filter or 'All frameworks',
            '{{NON_COMPLIANT_COUNT}}': str(summary['non_compliant']),
            '{{CRIT_COUNT}}':          str(sev('CRITICAL')),
            '{{HIGH_COUNT}}':          str(sev('HIGH')),
            '{{MED_COUNT}}':           str(sev('MEDIUM')),
            '{{LOW_COUNT}}':           str(sev('LOW')),
            '{{INFO_COUNT}}':          str(sev('INFORMATIONAL')),
            '{{CONTROLS_JSON}}':       json.dumps(findings_data).replace('</', '<\\/'),
            '{{REPORT_DATE}}':         datetime.now().strftime('%Y-%m-%d %H:%M'),
        }
        html = template
        for placeholder, value in substitutions.items():
            html = html.replace(placeholder, value)
    else:
        # Generate standalone HTML if template not found
        html = _generate_standalone_html(engine, findings_data, summary)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    return output_path


def _generate_stig_html_report(engine, output_path: str) -> str:
    """Generate STIG-specific HTML checklist report."""
    summary = engine.get_summary()
    stig_data = []

    for r in engine.all_results:
        sev = r.severity or r.control.severity or "MEDIUM"
        cat = _sev_to_cat(sev)
        # Map internal status to STIG standard terminology
        status_map = {
            "COMPLIANT": "Not a Finding",
            "NON_COMPLIANT": "Open",
            "NOT_APPLICABLE": "Not Applicable",
            "FALSE_POSITIVE": "Not a Finding",
            "NOT_TESTED": "Not Reviewed",
            "NEEDS_REVIEW": "Not Reviewed",
        }
        stig_status = status_map.get(r.status, "Not Reviewed")

        entry = {
            "id": r.control.control_id,
            "vulnId": r.control.vuln_id or r.control.control_id,
            "ruleId": r.control.rule_id or "",
            "name": r.control.name,
            "catLevel": cat,
            "severity": sev,
            "status": r.status,
            "stigStatus": stig_status,
            "srg": r.control.srg_ref or "",
            "ccis": r.control.ccis or [],
            "statement": r.control.statement or "",
            "checkContent": r.control.check_content or r.control.test_procedure or "",
            "fixText": r.remediation or r.control.fix_text or "",
            "evidence": r.evidence or "",
            "isFalsePositive": r.is_false_positive,
            "fpJustification": r.fp_justification or "",
        }
        stig_data.append(entry)

    # CAT-level counts for open findings only
    open_cat1 = sum(1 for e in stig_data if e["stigStatus"] == "Open" and e["catLevel"] == "CAT I")
    open_cat2 = sum(1 for e in stig_data if e["stigStatus"] == "Open" and e["catLevel"] == "CAT II")
    open_cat3 = sum(1 for e in stig_data if e["stigStatus"] == "Open" and e["catLevel"] == "CAT III")
    naf_count = sum(1 for e in stig_data if e["stigStatus"] == "Not a Finding")
    na_count  = sum(1 for e in stig_data if e["stigStatus"] == "Not Applicable")
    nr_count  = sum(1 for e in stig_data if e["stigStatus"] == "Not Reviewed")

    template_path = get_stig_template_path()
    if os.path.exists(template_path):
        with open(template_path, 'r', encoding='utf-8') as f:
            template = f.read()

        meta_script = f"""<script>
var STIG_META = {{
    target: {json.dumps(engine.target)},
    date: "{datetime.now().strftime('%Y-%m-%d %H:%M')}",
    tester: "Security Assessment Tool v1.0",
    totalRules: {summary['total']},
    openCat1: {open_cat1},
    openCat2: {open_cat2},
    openCat3: {open_cat3},
    nafCount: {naf_count},
    naCount:  {na_count},
    nrCount:  {nr_count}
}};
</script>"""
        controls_tag = ('<script type="application/json" id="sat-controls-data">'
                        + json.dumps(stig_data)
                        + '</script>')
        html = template.replace('</head>', meta_script + '\n</head>')
        html = html.replace('<!-- SAT-CONTROLS-PLACEHOLDER -->', controls_tag)
    else:
        html = _generate_stig_fallback_html(engine, stig_data, summary,
                                            open_cat1, open_cat2, open_cat3)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    return output_path


def generate_markdown_report(engine, output_path: str) -> str:
    """Generate structured Markdown report."""
    summary = engine.get_summary()
    findings = engine.get_findings()
    lines = []

    lines.append(f"# Security Assessment Report")
    lines.append(f"")
    lines.append(f"| Field | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| **Target** | {engine.target} |")
    lines.append(f"| **Type** | {engine.target_type} |")
    lines.append(f"| **Date** | {datetime.now().strftime('%Y-%m-%d %H:%M')} |")
    lines.append(f"| **Tool** | Security Assessment Tool v1.0 |")
    lines.append(f"| **Controls tested** | {summary['total']} |")
    lines.append(f"")

    lines.append(f"## Executive summary")
    lines.append(f"")
    lines.append(f"| Metric | Count |")
    lines.append(f"|---|---|")
    lines.append(f"| Compliant | {summary['compliant']} |")
    lines.append(f"| Non-compliant | {summary['non_compliant']} |")
    lines.append(f"| Not applicable | {summary['not_applicable']} |")
    lines.append(f"| False positives suppressed | {summary['false_positive']} |")
    lines.append(f"")
    lines.append(f"### Severity breakdown")
    lines.append(f"")
    lines.append(f"| Severity | Count |")
    lines.append(f"|---|---|")
    lines.append(f"| CRITICAL | {summary['critical']} |")
    lines.append(f"| HIGH | {summary['high']} |")
    lines.append(f"| MEDIUM | {summary['medium']} |")
    lines.append(f"| LOW | {summary['low']} |")
    lines.append(f"")

    lines.append(f"### Tier breakdown")
    lines.append(f"")
    lines.append(f"| Tier | Total | Findings |")
    lines.append(f"|---|---|---|")
    lines.append(f"| Automatic confirmation | {summary['auto_total']} | {summary['auto_findings']} |")
    lines.append(f"| Review required | {summary['review_total']} | — |")
    lines.append(f"| Manual confirmation | {summary['manual_total']} | — |")
    lines.append(f"")

    if findings:
        lines.append(f"## Findings")
        lines.append(f"")
        for r in findings:
            lines.append(f"### {r.control.control_id} — {r.control.name}")
            lines.append(f"")
            lines.append(f"- **Severity**: {r.severity}")
            lines.append(f"- **CIA**: {r.control.cia}")
            lines.append(f"- **Tier**: {r.tier}")
            lines.append(f"- **Reachability**: {r.reachability}")
            if r.cvss_score:
                lines.append(f"- **CVSS**: {r.cvss_score} ({r.cvss_vector})")
            lines.append(f"- **Evidence**: {r.evidence}")
            if r.remediation:
                lines.append(f"- **Remediation**: {r.remediation}")
            lines.append(f"")

    lines.append(f"## Compliant controls")
    lines.append(f"")
    for r in engine.all_results:
        if r.status == 'COMPLIANT':
            lines.append(f"- **{r.control.control_id}**: {r.control.name} — {r.evidence[:80] if r.evidence else 'Passed'}")
    lines.append(f"")

    lines.append(f"---")
    lines.append(f"*Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} by Security Assessment Tool v1.0*")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    return output_path


def generate_csv_report(engine, output_path: str) -> str:
    """Generate CSV export of all findings."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Control ID', 'Name', 'Family', 'Status', 'Severity', 'CIA',
        'Tier', 'Reachability', 'CVSS Score', 'CVSS Vector',
        'Evidence', 'Remediation', 'False Positive', 'FP Justification'
    ])

    for r in engine.all_results:
        writer.writerow([
            r.control.control_id, r.control.name, r.control.family,
            r.status, r.severity or r.control.severity, r.control.cia,
            r.tier, r.reachability, r.cvss_score, r.cvss_vector,
            r.evidence, r.remediation,
            'Yes' if r.is_false_positive else 'No', r.fp_justification
        ])

    with open(output_path, 'w', encoding='utf-8', newline='') as f:
        f.write(output.getvalue())

    return output_path


def generate_json_report(engine, output_path: str) -> str:
    """Generate JSON export with full metadata and audit trail."""
    summary = engine.get_summary()

    report = {
        "meta": {
            "tool": "Security Assessment Tool v1.0",
            "target": engine.target,
            "target_type": engine.target_type,
            "date": datetime.now().isoformat(),
            "system_id": engine.system_id,
            "scan_id": engine.scan_id,
            "control_sets": engine.selected_sets,
            "framework_filter": engine.framework_filter,
        },
        "summary": summary,
        "findings": [],
        "compliant": [],
        "false_positives": [],
    }

    for r in engine.all_results:
        entry = {
            "control_id": r.control.control_id,
            "name": r.control.name,
            "family": r.control.family,
            "status": r.status,
            "severity": r.severity or r.control.severity,
            "cia": r.control.cia,
            "tier": r.tier,
            "evidence": r.evidence,
            "confidence": r.confidence,
            "cvss_score": r.cvss_score,
            "cvss_vector": r.cvss_vector,
            "reachability": r.reachability,
            "remediation": r.remediation,
            "scanner": r.scanner_name,
        }

        if r.status == 'NON_COMPLIANT':
            report["findings"].append(entry)
        elif r.status == 'COMPLIANT':
            report["compliant"].append(entry)

        if r.is_false_positive:
            report["false_positives"].append({
                **entry,
                "justification": r.fp_justification,
            })

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return output_path


def _generate_stig_fallback_html(engine, stig_data, summary,
                                  open_cat1, open_cat2, open_cat3):
    """Minimal STIG report if stig-report-template.html is missing."""
    rows = ""
    for e in stig_data:
        rows += (f"<tr><td>{e['vulnId']}</td><td>{e['catLevel']}</td>"
                 f"<td>{e['name']}</td><td>{e['stigStatus']}</td>"
                 f"<td>{e['evidence'][:120]}</td></tr>")
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>STIG Assessment — {engine.target}</title>
<style>
body{{font-family:system-ui;background:#1a1a2e;color:#e0e0e0;margin:0;padding:20px}}
h1{{color:#fff}}table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #334155;padding:8px;text-align:left;vertical-align:top}}
th{{background:#1e293b}}.open{{color:#ef4444}}.naf{{color:#22c55e}}
</style></head><body>
<h1>STIG Compliance Assessment</h1>
<p>Target: {engine.target} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<p>Total: {summary['total']} rules | Open: CAT I={open_cat1}, CAT II={open_cat2}, CAT III={open_cat3}</p>
<table><tr><th>Vuln ID</th><th>CAT</th><th>Title</th><th>Status</th><th>Evidence</th></tr>
{rows}</table></body></html>"""


def _generate_standalone_html(engine, findings_data, summary):
    """Generate a standalone HTML report if the template is not available."""
    rows = []
    for item in findings_data:
        if item['status'] == 'NON_COMPLIANT':
            sev = item['severity'].lower()
            rows.append(
                '<tr>'
                '<td>' + item['id'] + '</td>'
                '<td>' + item['name'] + '</td>'
                '<td>' + item['status'] + '</td>'
                "<td class='" + sev + "'>" + item['severity'] + '</td>'
                '<td>' + item['evidence'][:100] + '</td>'
                '</tr>'
            )
    target = engine.target
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M')
    total = str(summary['total'])
    nc = str(summary['non_compliant'])
    comp = str(summary['compliant'])
    parts = [
        '<!DOCTYPE html>',
        "<html><head><meta charset='utf-8'>",
        '<title>Security Assessment - ' + target + '</title>',
        '<style>',
        'body{font-family:system-ui;background:#1a1a2e;color:#e0e0e0;margin:0;padding:20px}',
        'h1{color:#fff}table{border-collapse:collapse;width:100%}',
        'th,td{border:1px solid #333;padding:8px;text-align:left}',
        'th{background:#2a2a4a}.critical{color:#ff4444}.high{color:#ff8800}',
        '.medium{color:#4488ff}.low{color:#44cc44}',
        '</style></head><body>',
        '<h1>Security Assessment Report</h1>',
        '<p>Target: ' + target + ' | Date: ' + date_str + '</p>',
        '<p>Controls: ' + total + ' | Findings: ' + nc + ' | Compliant: ' + comp + '</p>',
        '<table><tr><th>ID</th><th>Name</th><th>Status</th><th>Severity</th><th>Evidence</th></tr>',
    ] + rows + ['</table></body></html>']
    return '\n'.join(parts)
