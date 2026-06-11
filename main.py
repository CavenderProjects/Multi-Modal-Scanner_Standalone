#!/usr/bin/env python3
"""Security Assessment Tool — GUI.

Three functions only:
  1. Target selection (single or multi-target, combine or separate reports)
  2. Load a previous HTML report to carry forward false positive markings
  3. Run assessment and produce reports

Screens:
  0 — Home     (configure targets, options)
  1 — Progress (live scanner feed)
  2 — Results  (stat cards + report links)
"""

import sys
import os
import webbrowser
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QListWidget, QListWidgetItem,
    QTextEdit, QStackedWidget, QProgressBar, QComboBox, QFileDialog,
    QMessageBox, QFrame, QDialog, QDialogButtonBox,
    QAbstractItemView, QScrollArea,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from db import init_db, SystemsDB, StigsDB
from detector import detect_target, extract_hostname
from controls import CONTROL_LIBRARIES
from engine import AssessmentEngine
from reporter import (
    generate_html_report, generate_markdown_report,
    generate_csv_report, generate_json_report,
    extract_prior_data_from_report,
)


# ── Colour palette (matches HTML report theme) ─────────────────────────────────

C = {
    'bg':       '#0f172a',
    'panel':    '#1e293b',
    'panel2':   '#273449',
    'code':     '#0b1220',
    'ink':      '#e2e8f0',
    'muted':    '#94a3b8',
    'border':   '#334155',
    'crit':     '#ef4444',
    'high':     '#f97316',
    'med':      '#eab308',
    'low':      '#3b82f6',
    'ok':       '#22c55e',
    'fp':       '#8b5cf6',
    'warn':     '#f59e0b',
    'sky':      '#38bdf8',
    'teal':     '#0e7490',
    'teal_h':   '#0891b2',
}

STYLESHEET = f"""
QMainWindow, QWidget, QDialog {{
    background-color: {C['bg']};
    color: {C['ink']};
    font-family: 'Segoe UI', system-ui, Arial, sans-serif;
}}
QLabel {{ color: {C['ink']}; }}

QLineEdit {{
    background-color: {C['panel']};
    color: {C['ink']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 7px 10px;
    font-family: 'Consolas', 'Cascadia Code', monospace;
    font-size: 13px;
}}
QLineEdit:focus {{ border-color: {C['sky']}; }}

QComboBox {{
    background-color: {C['panel']};
    color: {C['ink']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
}}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background-color: {C['panel2']};
    color: {C['ink']};
    border: 1px solid {C['border']};
    selection-background-color: {C['panel2']};
    selection-color: {C['sky']};
}}

QListWidget {{
    background-color: {C['panel']};
    color: {C['ink']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    font-size: 12px;
    outline: none;
}}
QListWidget::item {{ padding: 6px 10px; border-bottom: 1px solid {C['border']}; }}
QListWidget::item:last {{ border-bottom: none; }}
QListWidget::item:selected {{
    background-color: rgba(56, 189, 248, 0.1);
    color: {C['sky']};
    border-left: 2px solid {C['sky']};
}}

QPushButton {{
    background-color: {C['panel2']};
    color: {C['ink']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 12px;
    font-weight: 500;
}}
QPushButton:hover {{
    background-color: {C['border']};
    border-color: {C['muted']};
}}
QPushButton:pressed {{ background-color: {C['panel']}; }}
QPushButton:disabled {{
    background-color: {C['panel']};
    color: {C['border']};
    border-color: {C['border']};
}}

QProgressBar {{
    background-color: {C['panel2']};
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {C['teal']};
    border-radius: 4px;
}}

QTextEdit {{
    background-color: {C['code']};
    color: {C['ink']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 8px;
    font-family: 'Consolas', 'Cascadia Code', monospace;
    font-size: 11px;
    line-height: 1.5;
}}

QToolBar {{
    background-color: {C['panel']};
    border-bottom: 1px solid {C['border']};
    spacing: 6px;
    padding: 6px 10px;
}}
QToolBar QToolButton {{
    color: {C['muted']};
    background: transparent;
    border: none;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
}}
QToolBar QToolButton:hover {{
    color: {C['ink']};
    background-color: {C['panel2']};
}}

QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{
    background: {C['panel']};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {C['border']};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}

QFrame#sep {{ background-color: {C['border']}; max-height: 1px; min-height: 1px; }}
"""


# ── Reusable widgets ───────────────────────────────────────────────────────────

def _primary_btn(text):
    btn = QPushButton(text)
    btn.setStyleSheet(f"""
        QPushButton {{
            background-color: {C['teal']};
            color: #ffffff;
            border: none;
            border-radius: 6px;
            padding: 8px 24px;
            font-size: 13px;
            font-weight: 600;
        }}
        QPushButton:hover {{ background-color: {C['teal_h']}; }}
        QPushButton:disabled {{
            background-color: {C['panel2']};
            color: {C['border']};
        }}
    """)
    return btn


def _section_lbl(text):
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color: {C['muted']}; font-size: 10px; font-weight: 600;"
        f" letter-spacing: 0.08em; text-transform: uppercase;"
    )
    return lbl


def _sep():
    f = QFrame()
    f.setObjectName("sep")
    f.setFrameShape(QFrame.Shape.HLine)
    return f


def _stat_card(value, label, color):
    card = QFrame()
    card.setStyleSheet(
        f"background-color: {C['panel']}; border: 1px solid {C['border']};"
        f" border-radius: 8px; padding: 4px;"
    )
    lay = QVBoxLayout(card)
    lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lay.setSpacing(2)
    num = QLabel(str(value))
    num.setAlignment(Qt.AlignmentFlag.AlignCenter)
    num.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: 600; border: none;")
    tag = QLabel(label)
    tag.setAlignment(Qt.AlignmentFlag.AlignCenter)
    tag.setStyleSheet(f"color: {C['muted']}; font-size: 11px; border: none;")
    lay.addWidget(num)
    lay.addWidget(tag)
    return card


# ── Target type helpers ────────────────────────────────────────────────────────

# Map target type → control library keys to load automatically
_TYPE_SETS = {
    'website':       ['website_agent'],
    'agent':         ['website_agent'],
    'api':           ['api'],
    'code':          ['code_review'],
    'stig':          [],   # uses stig_paths
    'os':            ['os_software'],
    'interconnected':['interconnected'],
}

_TYPE_META = {
    # type → (badge_bg, badge_fg, short_label)
    'website':       (C['low'],    '#bfdbfe', 'Website'),
    'api':           ('#534AB7',   '#e0ddfe', 'API'),
    'code':          (C['ok'],     '#bbf7d0', 'Code'),
    'agent':         (C['high'],   '#fed7aa', 'Agent'),
    'stig':          (C['fp'],     '#ddd6fe', 'STIG'),
    'os':            (C['teal'],   '#99f6e4', 'OS/SW'),
    'interconnected':(C['crit'],   '#fecaca', 'Interconnected'),
}


def _type_badge(type_str):
    bg, fg, label = _TYPE_META.get(type_str, (C['border'], C['muted'], 'Unknown'))
    return bg, fg, label


# ── Worker thread ──────────────────────────────────────────────────────────────

class ScanWorker(QThread):
    progress = pyqtSignal(str, str, str, list)
    finished = pyqtSignal(object)

    def __init__(self, engine):
        super().__init__()
        self.engine = engine

    def run(self):
        def cb(name, desc, status, results):
            self.progress.emit(name, desc, status, results)
        self.engine.run_automatic_tier(progress_callback=cb)
        self.finished.emit(self.engine)


# ── STIG Import Dialog ─────────────────────────────────────────────────────────

class StigImportDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Import DISA STIG")
        self.setMinimumWidth(520)
        self.setStyleSheet(STYLESHEET)
        self.stig_data = None

        lay = QVBoxLayout(self)
        lay.setSpacing(10)

        # File picker row
        file_row = QHBoxLayout()
        self.file_lbl = QLabel("No file selected")
        self.file_lbl.setStyleSheet(f"color: {C['muted']}; padding: 6px; font-size: 12px;")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        file_row.addWidget(self.file_lbl, 1)
        file_row.addWidget(browse)
        lay.addLayout(file_row)

        # Preview box
        self.preview = QLabel()
        self.preview.setWordWrap(True)
        self.preview.setStyleSheet(
            f"background-color: {C['panel2']}; border: 1px solid {C['border']};"
            f" border-radius: 6px; padding: 12px; color: {C['ink']}; font-size: 12px;"
        )
        self.preview.hide()
        lay.addWidget(self.preview)

        # Profile
        self.profile_lbl = _section_lbl("Assessment profile")
        self.profile_combo = QComboBox()
        self.profile_lbl.hide()
        self.profile_combo.hide()
        lay.addWidget(self.profile_lbl)
        lay.addWidget(self.profile_combo)

        # Dialog buttons
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("Import STIG")
        btns.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        self.ok_btn = btns.button(QDialogButtonBox.StandardButton.Ok)
        lay.addWidget(btns)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select STIG XCCDF XML", "",
            "XCCDF XML Files (*.xml);;All Files (*)"
        )
        if not path:
            return
        self.file_lbl.setText(os.path.basename(path))
        self.file_lbl.setStyleSheet(
            f"color: {C['ink']}; padding: 6px; font-size: 12px; font-weight: 500;"
        )
        try:
            tools_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"
            )
            sys.path.insert(0, tools_dir)
            from stig_parser import parse_stig
            parsed = parse_stig(path)
            self.stig_data = {'path': path, 'parsed': parsed}
            b, s = parsed['benchmark'], parsed['stats']
            self.preview.setText(
                f"<b>{b['title']}</b><br>"
                f"Version {b['version']} · {b['release_info']}<br>"
                f"{b['publisher']}<br><br>"
                f"Rules: {s['total_rules']} &nbsp;·&nbsp; "
                f"CAT I: {s['cat_i']} &nbsp;·&nbsp; "
                f"CAT II: {s['cat_ii']} &nbsp;·&nbsp; "
                f"CAT III: {s['cat_iii']}"
            )
            self.preview.show()
            self.profile_combo.clear()
            self.profile_combo.addItem(f"All rules ({s['total_rules']})")
            for p in parsed['profiles']:
                self.profile_combo.addItem(f"{p['title']} ({len(p['selected_rules'])})")
            self.profile_lbl.show()
            self.profile_combo.show()
            self.ok_btn.setEnabled(True)
        except Exception as e:
            crit_color = C['crit']
            self.preview.setText(f"<span style='color:{crit_color}'>Parse error: {e}</span>")
            self.preview.show()
            self.ok_btn.setEnabled(False)


# ── Main Window ────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Assessment Tool")
        self.setMinimumSize(860, 600)
        self.setStyleSheet(STYLESHEET)

        self.scan_worker       = None
        self.pending_configs   = []
        self.completed_engines = []
        self.prior_report_data = {}   # {control_id: {is_fp, justification, note}}
        self._scanner_count    = 0
        self._multi_mode       = "Separate reports"
        self._report_format    = "HTML dashboard + Markdown"

        # Outer wrapper: header + stacked screens
        outer = QWidget()
        outer_layout = QVBoxLayout(outer)
        outer_layout.setSpacing(0)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        outer_layout.addWidget(self._build_header())

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_home())
        self.stack.addWidget(self._build_progress())
        self.stack.addWidget(self._build_results())
        self.stack.setCurrentIndex(0)
        outer_layout.addWidget(self.stack)

        self.setCentralWidget(outer)
        init_db()

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = QWidget()
        hdr.setFixedHeight(48)
        hdr.setStyleSheet(
            f"background-color: {C['panel']};"
            f" border-bottom: 1px solid {C['border']};"
        )
        lay = QHBoxLayout(hdr)
        lay.setContentsMargins(20, 0, 20, 0)

        title = QLabel("Security Assessment Tool")
        title.setStyleSheet(
            f"color: {C['sky']}; font-size: 14px; font-weight: 700;"
            f" background: transparent; border: none;"
        )
        lay.addWidget(title)
        lay.addStretch()
        return hdr

    # ── Screen 0: Home ────────────────────────────────────────────────────────

    def _build_home(self):
        screen = QWidget()
        root = QVBoxLayout(screen)
        root.setSpacing(0)
        root.setContentsMargins(20, 16, 20, 0)

        # ── Target input ──
        tgt_hdr = QHBoxLayout()
        tgt_hdr.addWidget(_section_lbl("Targets"))
        tgt_hdr.addStretch()
        stig_btn = QPushButton("Import STIG…")
        stig_btn.clicked.connect(self._import_stig)
        tgt_hdr.addWidget(stig_btn)
        root.addLayout(tgt_hdr)
        root.addSpacing(6)

        input_row = QHBoxLayout()
        input_row.setSpacing(6)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText(
            "URL, file path, or API spec  ·  press Enter to add"
        )
        self.target_input.returnPressed.connect(self._add_target)
        browse_btn = QPushButton("Browse…")
        browse_btn.setFixedWidth(80)
        browse_btn.clicked.connect(self._browse_target)
        input_row.addWidget(self.target_input)
        input_row.addWidget(browse_btn)
        add_btn = QPushButton("Add")
        add_btn.setFixedWidth(50)
        add_btn.clicked.connect(self._add_target)
        input_row.addWidget(add_btn)
        root.addLayout(input_row)
        root.addSpacing(8)

        # ── Target list ──
        self.target_list = QListWidget()
        self.target_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.target_list.setMinimumHeight(140)
        root.addWidget(self.target_list)
        root.addSpacing(6)

        tgt_btns = QHBoxLayout()
        tgt_btns.setSpacing(8)
        remove_btn = QPushButton("Remove selected")
        remove_btn.clicked.connect(self._remove_selected)
        clear_btn = QPushButton("Clear all")
        clear_btn.clicked.connect(self._clear_targets)
        tgt_btns.addWidget(remove_btn)
        tgt_btns.addWidget(clear_btn)
        tgt_btns.addStretch()
        root.addLayout(tgt_btns)

        # ── Separator ──
        root.addSpacing(14)
        root.addWidget(_sep())
        root.addSpacing(14)

        # ── Options row ──
        opts = QHBoxLayout()
        opts.setSpacing(24)

        # FP carryover
        fp_col = QVBoxLayout()
        fp_col.setSpacing(6)
        fp_col.addWidget(_section_lbl("Previous report  ·  false positive carryover"))
        fp_inner = QHBoxLayout()
        fp_inner.setSpacing(8)
        load_btn = QPushButton("Load report…")
        load_btn.clicked.connect(self._load_previous_report)
        self.fp_label = QLabel("No report loaded")
        self.fp_label.setStyleSheet(f"color: {C['muted']}; font-size: 12px;")
        fp_inner.addWidget(load_btn)
        fp_inner.addWidget(self.fp_label, 1)
        fp_col.addLayout(fp_inner)
        opts.addLayout(fp_col, 3)

        # Divider
        vline = QFrame()
        vline.setFrameShape(QFrame.Shape.VLine)
        vline.setStyleSheet(f"color: {C['border']};")
        opts.addWidget(vline)

        # Mode + format
        rf_col = QVBoxLayout()
        rf_col.setSpacing(6)
        rf_col.addWidget(_section_lbl("Multi-target mode"))
        self.multi_mode_combo = QComboBox()
        self.multi_mode_combo.addItems(["Separate reports", "Combined report"])
        rf_col.addWidget(self.multi_mode_combo)

        rf_col.addSpacing(8)
        rf_col.addWidget(_section_lbl("Report format"))
        self.report_format_combo = QComboBox()
        self.report_format_combo.addItems([
            "HTML dashboard + Markdown",
            "HTML dashboard only",
            "Markdown only",
            "JSON",
        ])
        rf_col.addWidget(self.report_format_combo)
        opts.addLayout(rf_col, 2)

        root.addLayout(opts)
        root.addStretch()

        # ── Bottom bar ──
        root.addWidget(_sep())
        root.addSpacing(10)
        bottom = QHBoxLayout()
        self.home_status = QLabel("Add at least one target to begin")
        self.home_status.setStyleSheet(f"color: {C['muted']}; font-size: 12px;")
        self.run_btn = _primary_btn("▶  Run assessment")
        self.run_btn.clicked.connect(self._start_assessment)
        bottom.addWidget(self.home_status, 1)
        bottom.addWidget(self.run_btn)
        root.addLayout(bottom)
        root.addSpacing(12)

        return screen

    # ── Screen 1: Progress ────────────────────────────────────────────────────

    def _build_progress(self):
        screen = QWidget()
        lay = QVBoxLayout(screen)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(8)

        hdr = QHBoxLayout()
        self.scan_title = QLabel("Running assessment…")
        self.scan_title.setStyleSheet(
            f"color: {C['ink']}; font-size: 15px; font-weight: 600;"
        )
        self.scan_pct = QLabel("0%")
        self.scan_pct.setStyleSheet(
            f"color: {C['sky']}; font-size: 20px; font-weight: 600;"
        )
        hdr.addWidget(self.scan_title, 1)
        hdr.addWidget(self.scan_pct)
        lay.addLayout(hdr)

        self.scan_progress = QProgressBar()
        self.scan_progress.setMaximum(100)
        self.scan_progress.setFixedHeight(6)
        lay.addWidget(self.scan_progress)

        self.scan_status = QLabel("Initializing…")
        self.scan_status.setStyleSheet(f"color: {C['muted']}; font-size: 12px;")
        lay.addWidget(self.scan_status)

        lay.addSpacing(6)
        lay.addWidget(_section_lbl("Scanner activity"))
        self.scanner_feed = QTextEdit()
        self.scanner_feed.setReadOnly(True)
        self.scanner_feed.setFixedHeight(100)
        lay.addWidget(self.scanner_feed)

        lay.addWidget(_section_lbl("Live findings"))
        self.findings_feed = QTextEdit()
        self.findings_feed.setReadOnly(True)
        lay.addWidget(self.findings_feed)

        prog_bottom = QHBoxLayout()
        abort_btn = QPushButton("✕  Abort scan")
        abort_btn.clicked.connect(self._abort_scan)
        prog_bottom.addWidget(abort_btn)
        prog_bottom.addStretch()
        lay.addLayout(prog_bottom)

        return screen

    # ── Screen 2: Results ─────────────────────────────────────────────────────

    def _build_results(self):
        screen = QWidget()
        lay = QVBoxLayout(screen)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(10)

        self.results_banner = QLabel("Assessment complete")
        self.results_banner.setWordWrap(True)
        self.results_banner.setStyleSheet(f"""
            background-color: rgba(14, 116, 144, 0.12);
            color: {C['sky']};
            border: 1px solid rgba(14, 116, 144, 0.4);
            border-radius: 8px;
            padding: 14px 16px;
            font-size: 13px;
            font-weight: 500;
        """)
        lay.addWidget(self.results_banner)

        self.stats_row = QHBoxLayout()
        self.stats_row.setSpacing(10)
        lay.addLayout(self.stats_row)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.results_panel = QWidget()
        self.results_panel.setStyleSheet(f"background-color: {C['bg']};")
        self.results_layout = QVBoxLayout(self.results_panel)
        scroll.setWidget(self.results_panel)
        lay.addWidget(scroll)

        bottom = QHBoxLayout()
        new_btn = QPushButton("＋ New scan")
        new_btn.clicked.connect(self._reset_to_home)
        bottom.addWidget(new_btn)
        bottom.addStretch()
        lay.addLayout(bottom)

        return screen

    # ── Target helpers ────────────────────────────────────────────────────────

    def _add_target(self):
        text = self.target_input.text().strip()
        if not text:
            return
        t = detect_target(text)['type']
        _, _, lbl = _type_badge(t)
        item = QListWidgetItem(f"[{lbl}]  {text}")
        item.setData(Qt.ItemDataRole.UserRole, {'target': text, 'type': t})
        self.target_list.addItem(item)
        self.target_input.clear()
        self._refresh_status()

    def _browse_target(self):
        """Open a file/folder picker and add the selection as a target."""
        # Ask whether the user wants a file or a folder
        msg = QMessageBox(self)
        msg.setWindowTitle("Browse target")
        msg.setText("What would you like to browse for?")
        msg.setStyleSheet(STYLESHEET)
        file_btn   = msg.addButton("File",   QMessageBox.ButtonRole.AcceptRole)
        folder_btn = msg.addButton("Folder", QMessageBox.ButtonRole.AcceptRole)
        msg.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        msg.exec()

        clicked = msg.clickedButton()
        if clicked == file_btn:
            path, _ = QFileDialog.getOpenFileName(
                self, "Select target file", "",
                "All supported (*.py *.js *.ts *.rs *.java *.c *.cpp *.cs *.go *.php "
                "*.yaml *.yml *.json *.xml);;"
                "Source code (*.py *.js *.ts *.rs *.java *.c *.cpp *.cs *.go *.php);;"
                "API specs (*.yaml *.yml *.json);;"
                "STIG XML (*.xml);;"
                "All files (*)"
            )
        elif clicked == folder_btn:
            path = QFileDialog.getExistingDirectory(
                self, "Select target folder"
            )
        else:
            return

        if not path:
            return
        self.target_input.setText(path)
        self._add_target()

    def _remove_selected(self):
        for item in self.target_list.selectedItems():
            self.target_list.takeItem(self.target_list.row(item))
        self._refresh_status()

    def _clear_targets(self):
        self.target_list.clear()
        self._refresh_status()

    def _refresh_status(self):
        n = self.target_list.count()
        if n == 0:
            self.home_status.setText("Add at least one target to begin")
        elif n == 1:
            self.home_status.setText("1 target queued")
        else:
            self.home_status.setText(
                f"{n} targets queued  ·  interconnected controls will be included"
            )

    # ── FP carryover ─────────────────────────────────────────────────────────

    def _load_previous_report(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load previous assessment report", "",
            "HTML Reports (*.html);;All Files (*)"
        )
        if not path:
            return

        # Validate it is actually one of our assessment reports
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except OSError as e:
            QMessageBox.warning(self, "Cannot read file", f"Could not open file:\n{e}")
            return

        if 'sat-controls-data' not in content:
            QMessageBox.warning(
                self,
                "Not a valid report",
                f"{os.path.basename(path)}\n\n"
                "This does not appear to be a Security Assessment Tool report.\n"
                "Please select an HTML report generated by this tool."
            )
            return

        prior_data = extract_prior_data_from_report(path)
        self.prior_report_data = prior_data
        name = os.path.basename(path)
        n_fp    = sum(1 for v in prior_data.values() if v.get('is_fp'))
        n_notes = sum(1 for v in prior_data.values() if v.get('note'))
        parts = []
        if n_fp:
            parts.append(f"{n_fp} false positive{'s' if n_fp != 1 else ''}")
        if n_notes:
            parts.append(f"{n_notes} note{'s' if n_notes != 1 else ''}")
        if parts:
            self.fp_label.setText(f"{name}  ·  {', '.join(parts)} will carry forward")
            self.fp_label.setStyleSheet(f"color: {C['ok']}; font-size: 12px;")
        else:
            self.fp_label.setText(f"{name}  ·  No false positives or notes found")
            self.fp_label.setStyleSheet(f"color: {C['muted']}; font-size: 12px;")

    # ── STIG import ───────────────────────────────────────────────────────────

    def _import_stig(self):
        dialog = StigImportDialog(self)
        if not (dialog.exec() and dialog.stig_data):
            return
        parsed = dialog.stig_data['parsed']
        b, s = parsed['benchmark'], parsed['stats']

        tools_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"
        )
        sys.path.insert(0, tools_dir)
        from stig_parser import to_markdown

        refs_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "references"
        )
        safe = b['id'].replace(' ', '_').lower()
        md_path = os.path.join(refs_dir, f"stig-{safe}-controls.md")
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(to_markdown(parsed, include_profiles=True))

        StigsDB.save(
            b['id'], b['title'], b['version'], b['release_info'],
            s['total_rules'], dialog.stig_data['path'], md_path
        )

        # Add to target list instead of a separate control set list
        item = QListWidgetItem(f"[STIG]  {b['title']}  ({s['total_rules']} rules)")
        item.setData(Qt.ItemDataRole.UserRole, {
            'target':       dialog.stig_data['path'],
            'type':         'stig',
            'stig_md_path': md_path,
        })
        self.target_list.addItem(item)
        self._refresh_status()

        QMessageBox.information(
            self, "STIG Imported",
            f"Imported: {b['title']}\n"
            f"{s['total_rules']} rules  (CAT I: {s['cat_i']}, "
            f"CAT II: {s['cat_ii']}, CAT III: {s['cat_iii']})\n\n"
            f"Added to targets list."
        )

    # ── Assessment ────────────────────────────────────────────────────────────

    def _start_assessment(self):
        if self.target_list.count() == 0:
            QMessageBox.warning(self, "No targets", "Add at least one target.")
            return

        multi_target = self.target_list.count() > 1

        self.pending_configs = []
        for i in range(self.target_list.count()):
            d = self.target_list.item(i).data(Qt.ItemDataRole.UserRole)
            target      = d['target']
            target_type = d['type'] if d['type'] != 'unknown' else 'website'

            # Auto-select control sets from target type
            if target_type == 'stig':
                selected_sets = []
                stig_paths    = [d.get('stig_md_path', '')]
            else:
                selected_sets = list(_TYPE_SETS.get(target_type, ['website_agent']))
                stig_paths    = []

            # When assessing multiple targets together, add interconnected controls
            if multi_target and target_type != 'stig' and 'interconnected' not in selected_sets:
                selected_sets.append('interconnected')

            hostname = (
                extract_hostname(target)
                if target_type in ('website', 'api', 'agent')
                else target
            )
            system = SystemsDB.get_or_create(target, target_type, hostname)
            self.pending_configs.append({
                'target':        target,
                'target_type':   target_type,
                'selected_sets': selected_sets,
                'stig_paths':    stig_paths,
                'system_id':     system['id'],
            })

        self.completed_engines = []
        self._multi_mode    = self.multi_mode_combo.currentText()
        self._report_format = self.report_format_combo.currentText()
        self._scanner_count = 0

        self.scanner_feed.clear()
        self.findings_feed.clear()
        self.scan_progress.setValue(0)
        self.scan_pct.setText("0%")
        self.stack.setCurrentIndex(1)
        self._run_next_target()

    def _run_next_target(self):
        if not self.pending_configs:
            self._all_done()
            return

        cfg  = self.pending_configs.pop(0)
        done = len(self.completed_engines)
        total = done + 1 + len(self.pending_configs)
        self.scan_title.setText(f"Target {done + 1} of {total}  ·  {cfg['target']}")
        self.scan_status.setText("Loading controls…")

        engine = AssessmentEngine(
            target=cfg['target'],
            target_type=cfg['target_type'],
            system_id=cfg['system_id'],
            selected_sets=cfg['selected_sets'],
            stig_paths=cfg['stig_paths'],
            prior_report_data=self.prior_report_data,
        )
        engine.load_controls()
        engine.start_scan()
        self.scan_status.setText("Scanning…")

        self.scan_worker = ScanWorker(engine)
        self.scan_worker.progress.connect(self._on_progress)
        self.scan_worker.finished.connect(self._on_target_done)
        self.scan_worker.start()

    def _on_progress(self, name, desc, status, results):
        if status == 'running':
            self.scanner_feed.append(f"  {name}: {desc}…")
            self.scan_status.setText(f"Running {name}…")
        elif status == 'done':
            self._scanner_count += 1
            pct = min(int(self._scanner_count / max(10, self._scanner_count + 2) * 90), 90)
            self.scan_progress.setValue(pct)
            self.scan_pct.setText(f"{pct}%")
            self.scanner_feed.append(f"  ✓ {name}")
            for r in results:
                if r.status == 'NON_COMPLIANT':
                    sev = r.severity or 'MEDIUM'
                    self.findings_feed.append(
                        f"  [{sev}]  {r.control_id} — {r.evidence[:80]}"
                    )

    def _on_target_done(self, engine):
        self.completed_engines.append(engine)
        self.scan_progress.setValue(95)
        self.scan_pct.setText("95%")
        self.scan_status.setText(
            "Generating reports…" if not self.pending_configs else "Done."
        )
        self._run_next_target()

    def _all_done(self):
        self.scan_progress.setValue(100)
        self.scan_pct.setText("100%")

        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(output_dir, exist_ok=True)

        report_paths = []

        if self._multi_mode == "Combined report" and len(self.completed_engines) > 1:
            primary = self.completed_engines[0]
            for eng in self.completed_engines[1:]:
                primary.all_results.extend(eng.all_results)
                primary.auto_results.extend(eng.auto_results)
                primary.review_items.extend(eng.review_items)
                primary.manual_items.extend(eng.manual_items)
            primary.target = ", ".join(e.target for e in self.completed_engines)
            paths = self._write_reports(primary, output_dir)
            report_paths.extend(paths)
            primary.complete(paths[0] if paths else None)
        else:
            for engine in self.completed_engines:
                paths = self._write_reports(engine, output_dir)
                report_paths.extend(paths)
                engine.complete(paths[0] if paths else None)

        self._show_results(report_paths)

    def _write_reports(self, engine, output_dir) -> list:
        ts   = datetime.now().strftime("%Y-%m-%d %I.%M%p").lower()
        raw  = (
            extract_hostname(engine.target)
            if engine.target.startswith('http')
            else os.path.basename(engine.target.rstrip('/\\')) or engine.target
        )
        safe = (
            raw.replace('/', '_').replace('\\', '_')
               .replace(',', '-').replace(' ', '_')[:40]
        )
        type_prefix = {
            'website':  'website',
            'api':      'api',
            'code':     'code-review',
            'agent':    'agent',
            'stig':     'stig',
        }.get(getattr(engine, 'target_type', ''), 'assessment')
        base = os.path.join(output_dir, f"{type_prefix}_{safe}_{ts}")
        fmt  = self._report_format
        paths = []

        if "HTML" in fmt or "+" in fmt:
            paths.append(generate_html_report(engine, base + ".html"))
        if "Markdown" in fmt or "+" in fmt:
            p = generate_markdown_report(engine, base + ".md")
            if not paths:
                paths.append(p)
        if "JSON" in fmt:
            p = generate_json_report(engine, base + ".json")
            if not paths:
                paths.append(p)

        generate_csv_report(engine, base + ".csv")
        return paths

    # ── Results screen ────────────────────────────────────────────────────────

    def _show_results(self, report_paths: list):
        total   = sum(len(e.all_results) for e in self.completed_engines)
        nc      = sum(
            sum(1 for r in e.all_results if r.status == 'NON_COMPLIANT')
            for e in self.completed_engines
        )
        crit    = sum(
            sum(1 for r in e.all_results
                if r.status == 'NON_COMPLIANT' and r.severity == 'CRITICAL')
            for e in self.completed_engines
        )
        high    = sum(
            sum(1 for r in e.all_results
                if r.status == 'NON_COMPLIANT' and r.severity == 'HIGH')
            for e in self.completed_engines
        )
        comp    = sum(
            sum(1 for r in e.all_results if r.status == 'COMPLIANT')
            for e in self.completed_engines
        )
        fp      = sum(
            sum(1 for r in e.all_results if r.is_false_positive)
            for e in self.completed_engines
        )

        n    = len(self.completed_engines)
        tgts = ", ".join(e.target for e in self.completed_engines[:3])
        if n > 3:
            tgts += f"  +{n - 3} more"

        self.results_banner.setText(
            f"Assessment complete  ·  {n} target{'s' if n > 1 else ''}  ·  "
            f"{total} controls evaluated  ·  {nc} findings  ·  "
            f"{fp} false positive{'s' if fp != 1 else ''} suppressed\n{tgts}"
        )

        # Rebuild stat cards
        while self.stats_row.count():
            w = self.stats_row.takeAt(0)
            if w.widget():
                w.widget().deleteLater()

        for lbl, val, color in [
            ("Controls tested", total, C['ink']),
            ("Critical",        crit,  C['crit']),
            ("High",            high,  C['high']),
            ("Compliant",       comp,  C['ok']),
            ("Suppressed",       fp,    C['fp']),
        ]:
            self.stats_row.addWidget(_stat_card(val, lbl, color))

        # Rebuild report links
        while self.results_layout.count():
            w = self.results_layout.takeAt(0)
            if w.widget():
                w.widget().deleteLater()

        self.results_layout.addSpacing(8)
        self.results_layout.addWidget(_section_lbl("Generated reports"))
        self.results_layout.addSpacing(6)

        for path in report_paths:
            if not os.path.exists(path):
                continue
            row_widget = QWidget()
            row_widget.setStyleSheet(
                f"background-color: {C['panel']}; border: 1px solid {C['border']};"
                f" border-radius: 6px; padding: 2px;"
            )
            row = QHBoxLayout(row_widget)
            row.setContentsMargins(12, 8, 12, 8)

            name_lbl = QLabel(os.path.basename(path))
            name_lbl.setStyleSheet(
                f"color: {C['ink']}; font-size: 12px; font-family: monospace;"
                f" background: transparent; border: none;"
            )
            row.addWidget(name_lbl, 1)

            is_html = path.endswith('.html')
            open_btn = QPushButton("Open in browser" if is_html else "Open")
            open_btn.setFixedWidth(120)
            if is_html:
                open_btn.clicked.connect(
                    lambda _, p=path: webbrowser.open('file:///' + p.replace(os.sep, '/'))
                )
            else:
                open_btn.clicked.connect(
                    lambda _, p=path: (
                        os.startfile(p) if os.name == 'nt'
                        else webbrowser.open('file:///' + p)
                    )
                )
            row.addWidget(open_btn)
            self.results_layout.addWidget(row_widget)
            self.results_layout.addSpacing(4)

        self.results_layout.addStretch()
        self.stack.setCurrentIndex(2)

    # ── Reset ─────────────────────────────────────────────────────────────────

    def _abort_scan(self):
        """Disconnect worker signals then navigate home.

        The thread may still be running in the background, but disconnecting
        its signals prevents it from touching UI state or triggering report
        generation after the user has moved on.
        """
        if self.scan_worker and self.scan_worker.isRunning():
            try:
                self.scan_worker.progress.disconnect()
                self.scan_worker.finished.disconnect()
            except RuntimeError:
                pass  # already disconnected
            self.scan_worker = None
        self._reset_to_home()

    def _reset_to_home(self):
        self.completed_engines = []
        self.pending_configs   = []
        self._scanner_count    = 0
        self.stack.setCurrentIndex(0)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
