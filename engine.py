"""Assessment engine — orchestrates the 3-tier assessment flow.

Tier 1 (Automatic confirmation): Runs scanners, applies rules, pass/fail.
Tier 2 (Review required): Collects evidence, calculates confidence, queues for user.
Tier 3 (Manual confirmation): Presents checklist, user answers from knowledge.

Integrates with DB for prior decisions and false positive suppression.
"""

import time
import os
from dataclasses import dataclass, field
from typing import Optional, Callable
from controls import Control, load_all_controls, get_tier_counts
from scanners import run_all_scanners, ScanResult
from db import (init_db, SystemsDB, ScansDB, DecisionsDB,
                FalsePositivesDB, FindingsDB, evidence_hash)

try:
    from code_scanner import scan_target as scan_code
except ImportError:
    scan_code = None

try:
    from api_scanner import scan_spec as scan_api
except ImportError:
    scan_api = None

try:
    from agent_scanner import scan_agent_config as scan_agent
except ImportError:
    scan_agent = None

try:
    from os_scanner import scan_os_target as scan_os
except ImportError:
    scan_os = None


@dataclass
class AssessmentResult:
    control: Control
    status: str = "NOT_TESTED"  # COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE, NEEDS_REVIEW, ERROR
    tier: str = ""
    severity: str = ""
    evidence: str = ""
    confidence: float = 1.0
    cvss_score: float = 0.0
    cvss_vector: str = ""
    reachability: str = ""
    remediation: str = ""
    is_false_positive: bool = False
    fp_justification: str = ""
    prior_decision: Optional[dict] = None
    prior_evidence_changed: bool = False
    user_decision: str = ""
    user_notes: str = ""
    scanner_name: str = ""


class AssessmentEngine:
    """Orchestrates the full 3-tier assessment."""

    def __init__(self, target: str, target_type: str, system_id: int,
                 selected_sets: list, stig_paths: list = None,
                 framework_filter: str = None, use_prior: bool = False,
                 prior_fp_ids: set = None,
                 prior_report_data: dict = None):
        self.target = target
        self.target_type = target_type
        self.system_id = system_id
        self.selected_sets = selected_sets
        self.stig_paths = stig_paths or []
        self.framework_filter = framework_filter
        self.use_prior = use_prior
        # prior_report_data is the authoritative source; prior_fp_ids kept for compat
        if prior_report_data is not None:
            self.prior_report_data = prior_report_data
            self.prior_fp_ids = {cid for cid, v in prior_report_data.items() if v.get('is_fp')}
        else:
            self.prior_report_data = {}
            self.prior_fp_ids = prior_fp_ids or set()

        self.controls = []
        self.auto_results = []
        self.review_items = []
        self.manual_items = []
        self.all_results = []
        self.scan_id = None
        self.false_positives = []

    def load_controls(self):
        """Load and classify all selected controls."""
        self.controls = load_all_controls(self.selected_sets, self.stig_paths)
        self.auto_results = []
        self.review_items = []
        self.manual_items = []

        for ctrl in self.controls:
            result = AssessmentResult(control=ctrl, tier=ctrl.tier)

            # Load prior decision if available
            prior = DecisionsDB.get_prior(self.system_id, ctrl.control_id)
            if prior:
                result.prior_decision = prior

            self.all_results.append(result)

            if ctrl.tier == "automatic_confirmation":
                self.auto_results.append(result)
            elif ctrl.tier == "review_required":
                self.review_items.append(result)
            else:
                self.manual_items.append(result)

        # Load false positives
        self.false_positives = FalsePositivesDB.get_active(self.system_id)

        return get_tier_counts(self.controls)

    def start_scan(self):
        """Create scan record in DB."""
        self.scan_id = ScansDB.create(
            self.system_id,
            control_sets=self.selected_sets,
            framework_filter=self.framework_filter
        )
        return self.scan_id

    def run_automatic_tier(self, progress_callback: Callable = None):
        """Run scanners and map results to automatic confirmation controls."""
        scan_results = []

        if self.target_type == 'code' and scan_code:
            scan_results = scan_code(self.target, progress_callback=progress_callback)
        elif self.target_type == 'api' and scan_api:
            scan_results = scan_api(self.target, progress_callback=progress_callback)
        elif self.target_type == 'os' and scan_os:
            scan_results = scan_os(self.target, progress_callback=progress_callback)
        elif self.target_type == 'agent' and scan_agent:
            # Run agent-specific analysis
            if os.path.isfile(self.target):
                scan_results = scan_agent(self.target, progress_callback=progress_callback)
            # Also run website scanners if it looks like a URL
            if self.target.startswith('http'):
                scan_results.extend(run_all_scanners(
                    self.target, self.target_type,
                    progress_callback=progress_callback
                ))
        else:
            # Website or fallback
            scan_results = run_all_scanners(
                self.target, self.target_type,
                progress_callback=progress_callback
            )

        # Map scanner results to controls
        result_by_ctrl = {}
        for sr in scan_results:
            if sr.control_id not in result_by_ctrl or sr.status == 'NON_COMPLIANT':
                result_by_ctrl[sr.control_id] = sr

        for ar in self.auto_results:
            ctrl_id = ar.control.control_id
            sr = result_by_ctrl.get(ctrl_id)

            if sr:
                ar.status = sr.status.replace('_', '-') if sr.status == 'NON_COMPLIANT' else sr.status
                if sr.status == 'NON_COMPLIANT':
                    ar.status = 'NON_COMPLIANT'
                elif sr.status == 'COMPLIANT':
                    ar.status = 'COMPLIANT'
                elif sr.status == 'NEEDS_REVIEW':
                    ar.status = 'NEEDS_REVIEW'
                    ar.tier = 'review_required'
                    self.review_items.append(ar)
                    continue
                else:
                    ar.status = sr.status

                ar.severity = sr.severity or ar.control.severity
                ar.evidence = sr.evidence
                ar.confidence = sr.confidence
                ar.cvss_score = sr.cvss_score
                ar.cvss_vector = sr.cvss_vector
                ar.reachability = sr.reachability or 'DIRECT'
                ar.remediation = sr.remediation
                ar.scanner_name = sr.scanner

                # Check false positive suppression
                fp_entry = next(
                    (fp for fp in self.false_positives if fp['control_id'] == ctrl_id),
                    None
                )
                if fp_entry:
                    ev_changed = FalsePositivesDB.check_evidence_changed(
                        self.system_id, ctrl_id, sr.evidence
                    )
                    if ev_changed:
                        ar.prior_evidence_changed = True
                    else:
                        ar.is_false_positive = True
                        ar.fp_justification = fp_entry['justification']
                        ar.status = 'FALSE_POSITIVE'
            else:
                # No direct scanner match — build contextual evidence
                family = ctrl_id.rsplit('-', 1)[0] if '-' in ctrl_id else ctrl_id
                related = [sr for sr in scan_results
                          if sr.control_id.startswith(family)]
                if related:
                    # Related controls tested — show for context only.
                    # Do NOT infer compliance from related results;
                    # each control must be independently confirmed.
                    ev_lines = [f"No scanner maps directly to {ctrl_id}, but related {family} controls were tested:"]
                    for rel in related[:5]:
                        status_tag = "PASS" if rel.status == 'COMPLIANT' else "FAIL"
                        ev_lines.append(f"  [{status_tag}] {rel.control_id}: {rel.evidence[:100]}")
                    ev_lines.append("")
                    ev_lines.append(f"Review the above evidence and manually confirm whether {ctrl_id} is met.")
                    ar.evidence = '\n'.join(ev_lines)
                    ar.status = 'NEEDS_REVIEW'  # Never infer status from related controls
                    ar.confidence = 0.5
                else:
                    ar.status = 'NEEDS_REVIEW'
                    ar.evidence = (f"No scanner covers {ctrl_id} directly.\n\n"
                                  f"Control: {ar.control.name}\n"
                                  f"Requirement: {ar.control.statement}\n\n"
                                  f"This control requires manual verification.")

            # Save to DB
            if self.scan_id:
                FindingsDB.save(
                    self.scan_id, ctrl_id, ar.tier, ar.status,
                    severity=ar.severity, evidence=ar.evidence,
                    confidence=ar.confidence, cvss_score=ar.cvss_score,
                    cvss_vector=ar.cvss_vector, reachability=ar.reachability,
                    remediation=ar.remediation, is_false_positive=ar.is_false_positive
                )

        # Also collect evidence for review tier
        # Build family-level evidence map for fuzzy matching
        family_evidence = {}
        for sr in scan_results:
            family = sr.control_id.rsplit('-', 1)[0] if '-' in sr.control_id else sr.control_id
            if family not in family_evidence:
                family_evidence[family] = []
            family_evidence[family].append(sr)

        for ar in self.review_items:
            ctrl_id = ar.control.control_id
            sr = result_by_ctrl.get(ctrl_id)

            if sr:
                # Direct match — scanner produced evidence for this exact control
                ar.evidence = sr.evidence
                ar.confidence = sr.confidence
                ar.severity = sr.severity or ar.control.severity
                ar.cvss_score = sr.cvss_score
                ar.cvss_vector = sr.cvss_vector
                ar.remediation = sr.remediation
                ar.scanner_name = sr.scanner
            else:
                # No direct match — build contextual evidence
                ar.severity = ar.control.severity
                family = ctrl_id.rsplit('-', 1)[0] if '-' in ctrl_id else ctrl_id
                related = family_evidence.get(family, [])

                evidence_parts = []
                evidence_parts.append(f"Control: {ar.control.name}")
                evidence_parts.append(f"Requirement: {ar.control.statement}")
                evidence_parts.append("")

                if related:
                    # Found related scanner results from the same family
                    evidence_parts.append(f"Related scanner evidence from {family} family:")
                    for rel_sr in related:
                        status_icon = "PASS" if rel_sr.status == 'COMPLIANT' else "FAIL" if rel_sr.status == 'NON_COMPLIANT' else "INFO"
                        evidence_parts.append(f"  [{status_icon}] {rel_sr.control_id}: {rel_sr.evidence[:120]}")
                    evidence_parts.append("")
                    evidence_parts.append(f"The scanner tested related controls in the {family} family. "
                                        f"This specific control ({ctrl_id}) requires manual review of "
                                        f"the evidence above to determine compliance.")
                    ar.confidence = 0.5
                    ar.scanner_name = related[0].scanner
                else:
                    # No related evidence at all — build target profile + structured checklist
                    # Target profile: summarise what the scanners actually covered
                    scanners_run = sorted({sr.scanner for sr in scan_results if sr.scanner})
                    tested_count = len(scan_results)
                    passed_count = sum(1 for sr in scan_results if sr.status == 'COMPLIANT')
                    failed_count = sum(1 for sr in scan_results if sr.status == 'NON_COMPLIANT')

                    evidence_parts.append("Target profile (from completed scanners):")
                    evidence_parts.append(f"  Target: {self.target}")
                    evidence_parts.append(f"  Type:   {self.target_type}")
                    if scanners_run:
                        evidence_parts.append(f"  Scanners run: {', '.join(scanners_run)}")
                    evidence_parts.append(f"  Controls tested by scanners: {tested_count} "
                                         f"({passed_count} pass, {failed_count} fail)")
                    evidence_parts.append("")
                    evidence_parts.append(f"No scanner covers {ctrl_id} ({ar.control.name}) — "
                                         f"this control requires manual assessment.")
                    evidence_parts.append("")

                    # Structured checklist from test procedure
                    if ar.control.test_procedure:
                        evidence_parts.append("Test procedure (from controls library):")
                        steps = [s.strip() for s in ar.control.test_procedure.split('.') if s.strip()]
                        for i, step in enumerate(steps[:6], 1):
                            evidence_parts.append(f"  [ ] {i}. {step}.")
                        evidence_parts.append("")
                    elif ar.control.statement:
                        evidence_parts.append("Requirement:")
                        evidence_parts.append(f"  {ar.control.statement[:400]}")
                        evidence_parts.append("")

                    evidence_parts.append("Assess manually and select: Accept finding / Compliant / N/A / False positive.")
                    ar.confidence = 0.2

                ar.evidence = '\n'.join(evidence_parts)
                if not ar.remediation:
                    ar.remediation = ar.control.fix_text or ar.control.statement

            # Check if prior decision exists and evidence hasn't changed
            if ar.prior_decision and self.use_prior:
                prior_hash = ar.prior_decision.get('evidence_hash', '')
                current_hash = evidence_hash(ar.evidence)
                if prior_hash == current_hash:
                    ar.prior_evidence_changed = False
                else:
                    ar.prior_evidence_changed = True

            # Check false positive
            fp_entry = next(
                (fp for fp in self.false_positives if fp['control_id'] == ctrl_id),
                None
            )
            if fp_entry:
                ev_changed = FalsePositivesDB.check_evidence_changed(
                    self.system_id, ctrl_id, ar.evidence
                )
                if not ev_changed:
                    ar.is_false_positive = True
                    ar.fp_justification = fp_entry['justification']
                else:
                    ar.prior_evidence_changed = True

        # Populate evidence / procedure for manual confirmation controls
        # (no scanner covers these; they were never touched above)
        for ar in self.manual_items:
            ctrl_id = ar.control.control_id
            ar.severity = ar.control.severity

            parts = []
            parts.append(f"Control: {ar.control.name}")
            if ar.control.statement:
                parts.append(f"Requirement: {ar.control.statement}")
            parts.append("")

            if ar.control.test_procedure:
                parts.append("Test procedure:")
                steps = [s.strip() for s in ar.control.test_procedure.split('.') if s.strip()]
                for i, step in enumerate(steps, 1):
                    parts.append(f"  {i}. {step}.")
                parts.append("")

            parts.append("No automated scanner covers this control.")
            parts.append("Complete the steps above then record your determination.")
            ar.evidence = '\n'.join(parts)

            if not ar.remediation:
                ar.remediation = ar.control.fix_text or ar.control.statement

        # Apply false positives and notes carried forward from a loaded previous report
        if self.prior_report_data or self.prior_fp_ids:
            for ar in self.all_results:
                cid = ar.control.control_id
                prior = self.prior_report_data.get(cid)
                if prior:
                    if prior.get('is_fp') and not ar.is_false_positive:
                        ar.is_false_positive = True
                        just = prior.get('justification', '').strip()
                        ar.fp_justification = just or "Carried forward from previous assessment report"
                        ar.status = 'FALSE_POSITIVE'
                    if prior.get('note') and not getattr(ar, 'user_notes', ''):
                        ar.user_notes = prior['note']
                elif cid in self.prior_fp_ids and not ar.is_false_positive:
                    # legacy path (prior_fp_ids supplied directly, no rich data)
                    ar.is_false_positive = True
                    ar.fp_justification = "Carried forward from previous assessment report"
                    ar.status = 'FALSE_POSITIVE'

    def apply_review_decision(self, index: int, decision: str,
                              notes: str = "", fp_justification: str = ""):
        """Apply user decision to a review_required item."""
        if index >= len(self.review_items):
            return
        ar = self.review_items[index]
        ar.user_decision = decision
        ar.user_notes = notes

        if decision == 'false_positive':
            ar.is_false_positive = True
            ar.fp_justification = fp_justification
            ar.status = 'FALSE_POSITIVE'
            FalsePositivesDB.add(self.system_id, ar.control.control_id,
                                fp_justification, ar.evidence)
        elif decision == 'accept':
            ar.status = 'NON_COMPLIANT'
        elif decision == 'compliant':
            ar.status = 'COMPLIANT'
        elif decision == 'na':
            ar.status = 'NOT_APPLICABLE'

        # Save decision
        DecisionsDB.save(
            self.system_id, ar.control.control_id, self.scan_id,
            'review_required', decision, ar.evidence, notes
        )
        if self.scan_id:
            FindingsDB.save(
                self.scan_id, ar.control.control_id, 'review_required',
                ar.status, severity=ar.severity, evidence=ar.evidence,
                confidence=ar.confidence, cvss_score=ar.cvss_score,
                cvss_vector=ar.cvss_vector, remediation=ar.remediation,
                is_false_positive=ar.is_false_positive
            )

    def apply_manual_decision(self, index: int, decision: str, notes: str = ""):
        """Apply user decision to a manual_confirmation item."""
        if index >= len(self.manual_items):
            return
        ar = self.manual_items[index]
        ar.user_decision = decision
        ar.user_notes = notes

        if decision == 'fail':
            ar.status = 'NON_COMPLIANT'
            ar.severity = ar.control.severity
        elif decision == 'pass':
            ar.status = 'COMPLIANT'
        elif decision == 'na':
            ar.status = 'NOT_APPLICABLE'

        DecisionsDB.save(
            self.system_id, ar.control.control_id, self.scan_id,
            'manual_confirmation', decision, notes=notes
        )
        if self.scan_id:
            FindingsDB.save(
                self.scan_id, ar.control.control_id, 'manual_confirmation',
                ar.status, severity=ar.severity, remediation=ar.control.fix_text
            )

    def apply_all_prior_manual(self):
        """Apply all prior decisions to manual items where available."""
        applied = 0
        for ar in self.manual_items:
            if ar.prior_decision and not ar.user_decision:
                decision = ar.prior_decision['decision']
                notes = ar.prior_decision.get('notes', '')
                self.apply_manual_decision(
                    self.manual_items.index(ar), decision, notes
                )
                applied += 1
        return applied

    def complete(self, report_path: str = None):
        """Finalize the scan, update DB."""
        findings = [r for r in self.all_results if r.status == 'NON_COMPLIANT']
        compliant = [r for r in self.all_results if r.status == 'COMPLIANT']

        if self.scan_id:
            ScansDB.complete(
                self.scan_id,
                controls_tested=len(self.all_results),
                findings_count=len(findings),
                compliant_count=len(compliant),
                report_path=report_path
            )
            SystemsDB.update_last_scanned(self.system_id)

    def get_summary(self) -> dict:
        """Get assessment summary statistics."""
        results = self.all_results
        return {
            'total': len(results),
            'compliant': sum(1 for r in results if r.status == 'COMPLIANT'),
            'non_compliant': sum(1 for r in results if r.status == 'NON_COMPLIANT'),
            'not_applicable': sum(1 for r in results if r.status == 'NOT_APPLICABLE'),
            'false_positive': sum(1 for r in results if r.is_false_positive),
            'not_tested': sum(1 for r in results if r.status == 'NOT_TESTED'),
            'critical': sum(1 for r in results if r.status == 'NON_COMPLIANT' and r.severity == 'CRITICAL'),
            'high': sum(1 for r in results if r.status == 'NON_COMPLIANT' and r.severity == 'HIGH'),
            'medium': sum(1 for r in results if r.status == 'NON_COMPLIANT' and r.severity == 'MEDIUM'),
            'low': sum(1 for r in results if r.status == 'NON_COMPLIANT' and r.severity == 'LOW'),
            'auto_total': len(self.auto_results),
            'review_total': len(self.review_items),
            'manual_total': len(self.manual_items),
            'auto_findings': sum(1 for r in self.auto_results if r.status == 'NON_COMPLIANT'),
            'review_decided': sum(1 for r in self.review_items if r.user_decision),
            'manual_decided': sum(1 for r in self.manual_items if r.user_decision),
        }

    def get_findings(self) -> list:
        """Get all non-compliant findings sorted by severity."""
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFORMATIONAL': 4}
        findings = [r for r in self.all_results
                    if r.status == 'NON_COMPLIANT' and not r.is_false_positive]
        return sorted(findings, key=lambda r: sev_order.get(r.severity, 5))
