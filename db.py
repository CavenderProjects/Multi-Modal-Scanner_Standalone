"""SQLite persistence layer for the security assessment tool.

Stores: target systems, scan history, per-control decisions, false positives,
and imported STIGs. Keyed by target+control for decision carry-forward.
"""

import sqlite3
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

DB_NAME = "assessments.db"


def get_db_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_NAME)


def get_connection():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS systems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            target_type TEXT NOT NULL,
            display_name TEXT,
            first_scanned TEXT NOT NULL,
            last_scanned TEXT,
            scan_count INTEGER DEFAULT 0,
            UNIQUE(target)
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id INTEGER NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            controls_tested INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            compliant_count INTEGER DEFAULT 0,
            control_sets TEXT,
            framework_filter TEXT,
            report_path TEXT,
            FOREIGN KEY (system_id) REFERENCES systems(id)
        );

        CREATE TABLE IF NOT EXISTS decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id INTEGER NOT NULL,
            control_id TEXT NOT NULL,
            scan_id INTEGER,
            tier TEXT NOT NULL,
            decision TEXT NOT NULL,
            evidence_hash TEXT,
            notes TEXT,
            decided_at TEXT NOT NULL,
            decided_by TEXT DEFAULT 'user',
            FOREIGN KEY (system_id) REFERENCES systems(id),
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            UNIQUE(system_id, control_id)
        );

        CREATE TABLE IF NOT EXISTS false_positives (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            system_id INTEGER NOT NULL,
            control_id TEXT NOT NULL,
            justification TEXT NOT NULL,
            evidence_hash TEXT,
            created_at TEXT NOT NULL,
            last_validated TEXT,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (system_id) REFERENCES systems(id),
            UNIQUE(system_id, control_id)
        );

        CREATE TABLE IF NOT EXISTS imported_stigs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stig_id TEXT NOT NULL,
            title TEXT NOT NULL,
            version TEXT,
            release_info TEXT,
            rule_count INTEGER,
            file_path TEXT,
            imported_at TEXT NOT NULL,
            controls_md_path TEXT,
            UNIQUE(stig_id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            control_id TEXT NOT NULL,
            tier TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT,
            evidence TEXT,
            confidence REAL,
            cvss_score REAL,
            cvss_vector TEXT,
            reachability TEXT,
            remediation TEXT,
            is_false_positive INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
    """)
    conn.commit()
    conn.close()


def evidence_hash(evidence_text):
    return hashlib.sha256((evidence_text or "").encode()).hexdigest()[:16]


class SystemsDB:
    @staticmethod
    def get_or_create(target, target_type, display_name=None):
        conn = get_connection()
        row = conn.execute("SELECT * FROM systems WHERE target=?", (target,)).fetchone()
        if row:
            conn.close()
            return dict(row)
        now = datetime.now().isoformat()
        cur = conn.execute(
            "INSERT INTO systems (target, target_type, display_name, first_scanned) VALUES (?,?,?,?)",
            (target, target_type, display_name or target, now)
        )
        system_id = cur.lastrowid
        conn.commit()
        row = conn.execute("SELECT * FROM systems WHERE id=?", (system_id,)).fetchone()
        conn.close()
        return dict(row)

    @staticmethod
    def get_all():
        conn = get_connection()
        rows = conn.execute("SELECT * FROM systems ORDER BY last_scanned DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def update_last_scanned(system_id):
        conn = get_connection()
        now = datetime.now().isoformat()
        conn.execute(
            "UPDATE systems SET last_scanned=?, scan_count=scan_count+1 WHERE id=?",
            (now, system_id)
        )
        conn.commit()
        conn.close()

    @staticmethod
    def find_by_target(target):
        conn = get_connection()
        row = conn.execute("SELECT * FROM systems WHERE target=?", (target,)).fetchone()
        conn.close()
        return dict(row) if row else None


class ScansDB:
    @staticmethod
    def create(system_id, control_sets=None, framework_filter=None):
        conn = get_connection()
        now = datetime.now().isoformat()
        cur = conn.execute(
            "INSERT INTO scans (system_id, started_at, control_sets, framework_filter) VALUES (?,?,?,?)",
            (system_id, now, json.dumps(control_sets or []), framework_filter)
        )
        scan_id = cur.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    @staticmethod
    def complete(scan_id, controls_tested, findings_count, compliant_count, report_path=None):
        conn = get_connection()
        now = datetime.now().isoformat()
        conn.execute(
            "UPDATE scans SET completed_at=?, controls_tested=?, findings_count=?, compliant_count=?, report_path=? WHERE id=?",
            (now, controls_tested, findings_count, compliant_count, report_path, scan_id)
        )
        conn.commit()
        conn.close()

    @staticmethod
    def get_history(system_id, limit=20):
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM scans WHERE system_id=? ORDER BY started_at DESC LIMIT ?",
            (system_id, limit)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


class DecisionsDB:
    @staticmethod
    def get_prior(system_id, control_id):
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM decisions WHERE system_id=? AND control_id=?",
            (system_id, control_id)
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def get_all_for_system(system_id):
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM decisions WHERE system_id=? ORDER BY decided_at DESC",
            (system_id,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def save(system_id, control_id, scan_id, tier, decision, evidence_text=None, notes=None):
        conn = get_connection()
        now = datetime.now().isoformat()
        eh = evidence_hash(evidence_text)
        conn.execute("""
            INSERT INTO decisions (system_id, control_id, scan_id, tier, decision, evidence_hash, notes, decided_at)
            VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(system_id, control_id) DO UPDATE SET
                scan_id=excluded.scan_id, decision=excluded.decision,
                evidence_hash=excluded.evidence_hash, notes=excluded.notes,
                decided_at=excluded.decided_at
        """, (system_id, control_id, scan_id, tier, decision, eh, notes, now))
        conn.commit()
        conn.close()


class FalsePositivesDB:
    @staticmethod
    def add(system_id, control_id, justification, evidence_text=None):
        conn = get_connection()
        now = datetime.now().isoformat()
        eh = evidence_hash(evidence_text)
        conn.execute("""
            INSERT INTO false_positives (system_id, control_id, justification, evidence_hash, created_at, last_validated)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(system_id, control_id) DO UPDATE SET
                justification=excluded.justification, evidence_hash=excluded.evidence_hash,
                last_validated=excluded.last_validated, is_active=1
        """, (system_id, control_id, justification, eh, now, now))
        conn.commit()
        conn.close()

    @staticmethod
    def get_active(system_id):
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM false_positives WHERE system_id=? AND is_active=1",
            (system_id,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def check_evidence_changed(system_id, control_id, new_evidence):
        conn = get_connection()
        row = conn.execute(
            "SELECT evidence_hash FROM false_positives WHERE system_id=? AND control_id=? AND is_active=1",
            (system_id, control_id)
        ).fetchone()
        conn.close()
        if not row:
            return False
        return row["evidence_hash"] != evidence_hash(new_evidence)

    @staticmethod
    def remove(system_id, control_id):
        conn = get_connection()
        conn.execute(
            "UPDATE false_positives SET is_active=0 WHERE system_id=? AND control_id=?",
            (system_id, control_id)
        )
        conn.commit()
        conn.close()


class StigsDB:
    @staticmethod
    def save(stig_id, title, version, release_info, rule_count, file_path, controls_md_path):
        conn = get_connection()
        now = datetime.now().isoformat()
        conn.execute("""
            INSERT INTO imported_stigs (stig_id, title, version, release_info, rule_count, file_path, imported_at, controls_md_path)
            VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(stig_id) DO UPDATE SET
                title=excluded.title, version=excluded.version, rule_count=excluded.rule_count,
                file_path=excluded.file_path, imported_at=excluded.imported_at,
                controls_md_path=excluded.controls_md_path
        """, (stig_id, title, version, release_info, rule_count, file_path, now, controls_md_path))
        conn.commit()
        conn.close()

    @staticmethod
    def get_all():
        conn = get_connection()
        rows = conn.execute("SELECT * FROM imported_stigs ORDER BY imported_at DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]


class FindingsDB:
    @staticmethod
    def save(scan_id, control_id, tier, status, severity=None, evidence=None,
             confidence=None, cvss_score=None, cvss_vector=None,
             reachability=None, remediation=None, is_false_positive=False):
        conn = get_connection()
        conn.execute("""
            INSERT INTO findings (scan_id, control_id, tier, status, severity, evidence,
                confidence, cvss_score, cvss_vector, reachability, remediation, is_false_positive)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (scan_id, control_id, tier, status, severity, evidence,
              confidence, cvss_score, cvss_vector, reachability, remediation,
              1 if is_false_positive else 0))
        conn.commit()
        conn.close()

    @staticmethod
    def get_for_scan(scan_id):
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
            "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 "
            "WHEN 'LOW' THEN 3 ELSE 4 END",
            (scan_id,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {get_db_path()}")
