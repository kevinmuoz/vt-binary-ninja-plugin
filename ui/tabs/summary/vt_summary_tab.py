"""
VT Summary Tab — VirusTotal detection summary for the current binary.

State machine pages:
  0  PAGE_NO_API_KEY  — API key not configured
  1  PAGE_LOADING     — Fetching report from VT
  2  PAGE_NOT_FOUND   — File not in VT (manual upload can be triggered from this tab)
  3  PAGE_UPLOADING   — Manual upload in progress
  4  PAGE_ERROR       — Network / API error
  5  PAGE_REPORT      — Full detection summary
"""

from __future__ import annotations

import webbrowser
import hashlib
import os
import logging
from datetime import datetime, timezone

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QCursor, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QToolButton,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from .widgets import DetectionDonut, FlowLayout, TagPill, VTColors
from ....virustotal.models import VTFileSummary
from ....core.vt_settings import settings
from ....virustotal.vtclient import VTClient
from ....virustotal.tasks.fetch_report import FetchReportTask
from ....virustotal.tasks.upload_file import UploadFileTask

VT_LOGO_RESOURCE = ":vtlogo/vt_logo.png"

CONTENT_BOX_STYLE = (
    f"QWidget#sectionBox {{ border: 1px solid {VTColors.SECTION_BORDER}; border-radius: 4px; }}"
)

def _ts_to_datetime(ts: int) -> str:
    """Format a Unix timestamp as 'YYYY-MM-DD HH:MM UTC'."""
    if ts <= 0:
        return "—"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

class VTSummaryTab(QWidget):
    PAGE_NO_API_KEY = 0
    PAGE_LOADING    = 1
    PAGE_NOT_FOUND  = 2
    PAGE_UPLOADING  = 3
    PAGE_ERROR      = 4
    PAGE_REPORT     = 5

    AV_PAGE_SIZE = 15
    AV_ORDER = {
        "malicious": 0, "suspicious": 1, "confirmed-timeout": 2,
        "timeout": 3, "undetected": 4, "harmless": 5,
        "failure": 6, "type-unsupported": 7,
    }

    def __init__(self, parent: QWidget, bv):
        super().__init__(parent)
        logging.debug("[VT SummaryTab] Initializing VTSummaryTab")
        self.bv = bv
        self._destroyed = False
        self._all_results_visible = False

        self._cached_summary: VTFileSummary | None = None
        self._cached_hash: str | None = None

        # Binjja background tasks
        self._fetch_task: FetchReportTask | None = None
        self._upload_task: UploadFileTask | None = None

        self.destroyed.connect(self._on_destroyed)
        self._build_ui()

    def _on_destroyed(self):
        self._destroyed = True

    def _is_alive(self) -> bool:
        if self._destroyed:
            return False
        try:
            _ = self.isVisible()
            return True
        except RuntimeError:
            self._destroyed = True
            return False

    def _has_api_key(self) -> bool:
        try:
            return settings.get_api_key().strip() != ""
        except Exception:
            return False

    def _get_api_key(self) -> str:
        try:
            return settings.get_api_key().strip()
        except Exception:
            return ""

    def _make_client(self) -> VTClient:
        return VTClient(self._get_api_key())

    def _get_file_hash(self) -> str | None:
        if self.bv is None:
            logging.debug("[VT] _get_file_hash: bv is None")
            return None
        try:
            filepath = self.bv.file.filename
            if not filepath or not os.path.isfile(filepath):
                logging.warning(f"[VT] File not on disk: {filepath!r}")
                return None
            with open(filepath, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            logging.debug(f"[VT] SHA256={h}")
            return h
        except Exception as e:
            logging.error(f"[VT] _get_file_hash error: {e}")
            return None

    def _invalidate_cache(self):
        self._cached_summary = None
        self._cached_hash = None

    # Public API
    def _update_ui_state(self):
        logging.debug("[VT SummaryTab] Updating UI state")
        if not self._is_alive():
            return

        if not self._has_api_key():
            self.stack.setCurrentIndex(self.PAGE_NO_API_KEY)
            return

        file_hash = self._get_file_hash()
        if not file_hash:
            logging.error("[VT SummaryTab] Could not compute file hash")
            self._show_error("Could not compute file hash.\nIs the file available on disk?")
            return

        if self._cached_hash == file_hash and self._cached_summary is not None:
            self._show_report(self._cached_summary)
            return

        self._fetch_report(file_hash)

    def refresh(self):
        self._invalidate_cache()
        self._update_ui_state()

    # UI construction
    def _build_ui(self):
        self.stack = QStackedWidget()
        # mm maybe i should use enum for these page indices at some point
        self.stack.addWidget(self._create_no_api_key_page())   # 0
        self.stack.addWidget(self._create_loading_page())      # 1
        self.stack.addWidget(self._create_not_found_page())    # 2
        self.stack.addWidget(self._create_uploading_page())    # 3
        self.stack.addWidget(self._create_error_page())        # 4
        self.stack.addWidget(self._create_report_page())       # 5

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.stack)
        self.stack.setCurrentIndex(self.PAGE_NOT_FOUND)

    # Page 0: No API key
    def _create_no_api_key_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 40, 20, 40)
        layout.addStretch(1)

        logo = QLabel()
        if VT_LOGO_RESOURCE:
            pix = QPixmap(VT_LOGO_RESOURCE)
            if not pix.isNull():
                logo.setPixmap(pix.scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo)
        layout.addSpacing(24)

        title = QLabel("API Key Required")
        title.setAlignment(Qt.AlignCenter)
        f = title.font()
        f.setPointSize(14)
        f.setBold(True)
        title.setFont(f)
        layout.addWidget(title)
        layout.addSpacing(16)

        msg = QLabel(
            "The <b>Summary</b> tab requires a VirusTotal API key.<br><br>"
            "Getting an API key is <b>free</b> and does not require a credit card.<br>"
            "Log in or create an account at "
            "<a href='https://www.virustotal.com'>VirusTotal</a>, "
            "copy your API key, and configure it in Settings."
        )
        msg.setWordWrap(True)
        msg.setAlignment(Qt.AlignCenter)
        msg.setTextFormat(Qt.RichText)
        msg.setOpenExternalLinks(True)
        layout.addWidget(msg)
        layout.addSpacing(24)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_refresh = QPushButton("Refresh")
        btn_refresh.setMinimumHeight(32)
        btn_refresh.setMinimumWidth(100)
        btn_refresh.clicked.connect(self._update_ui_state)
        btn_settings = QPushButton("Open Settings")
        btn_settings.setMinimumHeight(32)
        btn_settings.setMinimumWidth(120)
        btn_settings.clicked.connect(self._open_settings)
        btn_row.addWidget(btn_refresh)
        btn_row.addSpacing(12)
        btn_row.addWidget(btn_settings)
        btn_row.addStretch()
        layout.addLayout(btn_row)
        layout.addStretch(1)
        return page

    # Page 1: Loading
    def _create_loading_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 40, 20, 40)
        layout.addStretch(1)
        self._loading_label = QLabel("Checking VirusTotal…")
        self._loading_label.setAlignment(Qt.AlignCenter)
        f = self._loading_label.font()
        f.setPointSize(12)
        self._loading_label.setFont(f)
        self._loading_label.setStyleSheet(f"color: {VTColors.TEXT_PRIMARY};")
        layout.addWidget(self._loading_label)
        layout.addStretch(1)
        return page

    # Page 2: Not found 
    def _create_not_found_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 40, 20, 40)
        layout.addStretch(1)

        title = QLabel("File Not Found")
        title.setAlignment(Qt.AlignCenter)
        f = title.font()
        f.setPointSize(14)
        f.setBold(True)
        title.setFont(f)
        layout.addWidget(title)
        layout.addSpacing(12)

        self._not_found_msg = QLabel("This file has not been analyzed by VirusTotal yet.")
        self._not_found_msg.setAlignment(Qt.AlignCenter)
        self._not_found_msg.setWordWrap(True)
        self._not_found_msg.setStyleSheet(f"color: {VTColors.TEXT_PRIMARY};")
        layout.addWidget(self._not_found_msg)
        layout.addSpacing(24)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._btn_upload = QPushButton("Upload to VirusTotal")
        self._btn_upload.setMinimumHeight(32)
        self._btn_upload.setMinimumWidth(180)
        self._btn_upload.clicked.connect(self._on_upload_clicked)
        btn_row.addWidget(self._btn_upload)
        btn_row.addStretch()
        layout.addLayout(btn_row)
        layout.addStretch(1)
        return page

    # Page 3: Uploading
    def _create_uploading_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 40, 20, 40)
        layout.addStretch(1)

        self._uploading_label = QLabel("Uploading to VirusTotal…")
        self._uploading_label.setAlignment(Qt.AlignCenter)
        f = self._uploading_label.font()
        f.setPointSize(12)
        self._uploading_label.setFont(f)
        self._uploading_label.setStyleSheet(f"color: {VTColors.TEXT_PRIMARY};")
        layout.addWidget(self._uploading_label)
        layout.addSpacing(24)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._btn_check_report = QPushButton("Check Report")
        self._btn_check_report.setMinimumHeight(32)
        self._btn_check_report.setVisible(False)
        self._btn_check_report.clicked.connect(self.refresh)
        btn_row.addWidget(self._btn_check_report)
        btn_row.addStretch()
        layout.addLayout(btn_row)
        layout.addStretch(1)
        return page

    # Page 4: Error
    def _create_error_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 40, 20, 40)
        layout.addStretch(1)

        title = QLabel("Error")
        title.setAlignment(Qt.AlignCenter)
        f = title.font()
        f.setPointSize(14)
        f.setBold(True)
        title.setFont(f)
        layout.addWidget(title)
        layout.addSpacing(12)

        self._error_msg = QLabel("")
        self._error_msg.setAlignment(Qt.AlignCenter)
        self._error_msg.setWordWrap(True)
        self._error_msg.setStyleSheet(f"color: {VTColors.MALICIOUS};")
        layout.addWidget(self._error_msg)
        layout.addSpacing(24)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_retry = QPushButton("Retry")
        btn_retry.setMinimumHeight(32)
        btn_retry.clicked.connect(self.refresh)
        btn_row.addWidget(btn_retry)
        btn_row.addStretch()
        layout.addLayout(btn_row)
        layout.addStretch(1)
        return page

    # Page 5: Report
    def _create_report_page(self) -> QWidget:
        page = QWidget()

        scroll = QScrollArea(page)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self._report_container = QWidget()
        self._report_layout = QVBoxLayout(self._report_container)
        self._report_layout.setContentsMargins(8, 8, 8, 8)
        self._report_layout.setSpacing(0)

        scroll.setWidget(self._report_container)

        pl = QVBoxLayout(page)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.addWidget(scroll)
        return page

    # Open Settings
    def _open_settings(self):
        try:
            from binaryninjaui import UIContext
            ctx = UIContext.activeContext()
            if ctx:
                handler = ctx.contentActionHandler()
                if handler:
                    handler.executeAction("Settings")
        except Exception:
            pass

    # State transitions
    def _show_error(self, msg: str):
        self._error_msg.setText(msg)
        self.stack.setCurrentIndex(self.PAGE_ERROR)

    def _show_report(self, summary: VTFileSummary):
        self._populate_report(summary)
        self.stack.setCurrentIndex(self.PAGE_REPORT)

    # Network: Fetch report
    def _fetch_report(self, file_hash: str):
        self._loading_label.setText("Checking VirusTotal…")
        self.stack.setCurrentIndex(self.PAGE_LOADING)

        client = self._make_client()
        self._fetch_task = FetchReportTask(client, file_hash, parent=self)
        self._fetch_task.finished.connect(
            lambda code, summary, err: self._on_fetch_done(code, summary, err, file_hash)
        )
        self._fetch_task.start()

    def _on_fetch_done(
        self,
        status_code: int,
        summary: VTFileSummary | None,
        error_msg: str,
        file_hash: str,
    ):
        if not self._is_alive():
            return

        self._fetch_task = None

        if status_code == 200 and summary:
            self._cached_hash = file_hash
            self._cached_summary = summary
            self._show_report(summary)
        elif status_code == 404:
            self.stack.setCurrentIndex(self.PAGE_NOT_FOUND)
        else:
            self._show_error(error_msg or f"Unexpected error (HTTP {status_code})")

    # Network: Upload
    def _on_upload_clicked(self):
        self._start_upload()

    def _start_upload(self):
        if self.bv is None:
            self._show_error("No binary view available.")
            return

        filepath = self.bv.file.original_filename or self.bv.file.filename
        if not os.path.isfile(filepath):
            self._show_error("File not available on disk.")
            return

        self._uploading_label.setText("Uploading to VirusTotal…")
        self._btn_check_report.setVisible(False)
        self.stack.setCurrentIndex(self.PAGE_UPLOADING)

        self._upload_task = UploadFileTask(self._make_client(), filepath, parent=self)
        self._upload_task.finished.connect(self._on_upload_done)
        self._upload_task.start()

    def _on_upload_done(self, success: bool, error_msg: str):
        if not self._is_alive():
            return

        self._upload_task = None

        if success:
            self._uploading_label.setText(
                "Upload successful!\n\n"
                "VirusTotal is analyzing the file.\n"
                "This may take a few minutes."
            )
            self._btn_check_report.setVisible(True)
        else:
            self._show_error(f"Upload failed:\n{error_msg}")

    # Report population
    def _populate_report(self, s: VTFileSummary):
        layout = self._report_layout

        while layout.count():
            item = layout.takeAt(0)
            if w := item.widget():
                w.deleteLater()

        self._all_results_visible = False

        self._build_detection_section(s, layout)
        self._build_ai_section(s, layout)
        self._build_av_table_section(s, layout)
        layout.addStretch(1)

    # Section helper
    def _add_section(
        self,
        layout: QVBoxLayout,
        title: str,
        content: QWidget,
        right_widget: QWidget | None = None,
    ):
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 3)
        header.setSpacing(0)

        lbl = QLabel(title)
        f = lbl.font()
        f.setPointSize(10)
        f.setBold(True)
        lbl.setFont(f)
        lbl.setStyleSheet(f"color:{VTColors.TEXT_PRIMARY};")
        header.addWidget(lbl)
        header.addStretch(1)
        if right_widget:
            header.addWidget(right_widget)

        hw = QWidget()
        hw.setLayout(header)
        layout.addWidget(hw)

        content.setObjectName("sectionBox")
        content.setStyleSheet(CONTENT_BOX_STYLE)
        layout.addWidget(content)
        layout.addSpacing(10)

    # Detection section
    def _build_detection_section(self, s: VTFileSummary, layout: QVBoxLayout):
        # Header action buttons
        header_btns = QHBoxLayout()
        header_btns.setSpacing(6)
        header_btns.setContentsMargins(0, 0, 0, 0)

        btn_refresh = QToolButton()
        btn_refresh.setText("↻ Refresh")
        btn_refresh.setCursor(QCursor(Qt.PointingHandCursor))
        btn_refresh.setStyleSheet(
            f"QToolButton {{ color:{VTColors.TEXT_MUTED}; border:none; font-size:11px; padding:2px 4px; }}"
            f"QToolButton:hover {{ color:{VTColors.TEXT_SECONDARY}; }}"
        )
        btn_refresh.clicked.connect(self.refresh)

        btn_vt = QToolButton()
        btn_vt.setText("Open in VirusTotal ↗")
        btn_vt.setCursor(QCursor(Qt.PointingHandCursor))
        btn_vt.setStyleSheet(
            "QToolButton { color:#4a9eda; background:transparent;"
            "  border:1px solid #4a9eda; border-radius:3px;"
            "  padding:3px 8px; font-size:11px; }"
            "QToolButton:hover { background:rgba(74,158,218,0.15); }"
        )
        btn_vt.clicked.connect(
            lambda: webbrowser.open(
                f"https://www.virustotal.com/gui/file/{s.sha256}?utm=vt_bn_plugin"
            )
        )
        header_btns.addWidget(btn_refresh)
        header_btns.addWidget(btn_vt)
        btns_w = QWidget()
        btns_w.setLayout(header_btns)

        # Content box
        content = QWidget()
        outer = QVBoxLayout(content)
        outer.setContentsMargins(10, 8, 10, 8)
        outer.setSpacing(6)

        # Top row: donut + two-column info grid
        top_row = QHBoxLayout()
        top_row.setSpacing(14)
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.addWidget(DetectionDonut(s.stats))

        def info_cell(label: str, value: str, value_color: str = VTColors.TEXT_PRIMARY) -> QWidget:
            """Compact stacked label+value cell used inside the detection grid."""
            col = QVBoxLayout()
            col.setSpacing(1)
            col.setContentsMargins(0, 0, 0, 0)
            lbl = QLabel(label)
            lbl.setStyleSheet(f"color:{VTColors.TEXT_MUTED}; font-size:10px;")
            val = QLabel(value)
            val.setStyleSheet(f"font-size:11px; color:{value_color};")
            val.setWordWrap(True)
            col.addWidget(lbl)
            col.addWidget(val)
            w = QWidget()
            w.setLayout(col)
            return w

        score_str = f"{s.reputation:+d}" if s.reputation != 0 else "0"

        # Left column: Name, Type, Threat
        left_col = QVBoxLayout()
        left_col.setSpacing(5)
        left_col.setContentsMargins(0, 0, 0, 0)
        if s.meaningful_name:
            left_col.addWidget(info_cell("Name", s.meaningful_name))
        if s.type_description:
            left_col.addWidget(info_cell("Type", s.type_description))
        if s.suggested_threat_label:
            left_col.addWidget(info_cell("Threat", s.suggested_threat_label,
                                          value_color=VTColors.THREAT))
        left_col.addStretch(1)
        left_w = QWidget()
        left_w.setLayout(left_col)

        # Right column: Community Score, First seen, Last scan
        right_col = QVBoxLayout()
        right_col.setSpacing(5)
        right_col.setContentsMargins(0, 0, 0, 0)
        right_col.addWidget(info_cell("Community Score", score_str,
                                      value_color=VTColors.for_score(s.reputation)))
        if s.first_submission_date > 0:
            right_col.addWidget(info_cell("First seen", _ts_to_datetime(s.first_submission_date)))
        if s.last_analysis_date > 0:
            right_col.addWidget(info_cell("Last scan", _ts_to_datetime(s.last_analysis_date)))
        right_col.addStretch(1)
        right_w = QWidget()
        right_w.setLayout(right_col)

        top_row.addWidget(left_w, 3)
        top_row.addWidget(right_w, 2)
        top_row_w = QWidget()
        top_row_w.setLayout(top_row)
        outer.addWidget(top_row_w)

        # Tags row
        if s.tags:
            flow_w = QWidget()
            flow = FlowLayout(flow_w, h_spacing=5, v_spacing=4)
            for tag in s.tags:
                flow.addWidget(TagPill(tag))
            flow_w.setLayout(flow)
            outer.addWidget(flow_w)

        self._add_section(layout, "Detection", content, btns_w)

    # Code Insights section (only if exists)
    def _build_ai_section(self, s: VTFileSummary, layout: QVBoxLayout):
        if not s.ai_analysis:
            return

        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(10, 8, 10, 8)
        cl.setSpacing(6)

        if s.ai_verdict:
            badge_row = QHBoxLayout()
            badge_row.setContentsMargins(0, 0, 0, 0)
            vc = VTColors.for_verdict(s.ai_verdict)
            badge = QLabel(s.ai_verdict.upper())
            badge.setStyleSheet(
                f"color:{vc}; font-size:10px; font-weight:700;"
                f"border:1px solid {vc}; border-radius:3px; padding:1px 6px;"
            )
            badge_row.addWidget(badge)
            badge_row.addStretch(1)
            bw = QWidget()
            bw.setLayout(badge_row)
            cl.addWidget(bw)

        txt = QLabel(s.ai_analysis)
        txt.setWordWrap(True)
        txt.setStyleSheet("font-size:11px; color:#c8c8c8;")
        txt.setTextInteractionFlags(Qt.TextSelectableByMouse)
        cl.addWidget(txt)
        self._add_section(layout, "Code Insights", content)

    # AV table section
    def _build_av_table_section(self, s: VTFileSummary, layout: QVBoxLayout):
        self._sorted_av = sorted(
            s.engine_results,
            key=lambda r: (self.AV_ORDER.get(r.category, 9), r.engine_name),
        )

        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)

        self._av_table = QTableWidget(0, 2)
        self._av_table.setHorizontalHeaderLabels(["Engine", "Result"])
        self._av_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self._av_table.setColumnWidth(0, 85)
        self._av_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._av_table.horizontalHeader().setFixedHeight(22)
        self._av_table.horizontalHeader().setStyleSheet("font-size:10px;")
        self._av_table.verticalHeader().setVisible(False)
        self._av_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._av_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._av_table.setAlternatingRowColors(True)
        self._av_table.setShowGrid(False)
        self._av_table.verticalHeader().setDefaultSectionSize(22)
        self._av_table.setStyleSheet("QTableWidget { font-size:11px; border:none; }")
        self._av_table.setFrameShape(QFrame.NoFrame)

        self._populate_av_table(self.AV_PAGE_SIZE)
        cl.addWidget(self._av_table)

        if len(self._sorted_av) > self.AV_PAGE_SIZE:
            self._toggle_btn = QToolButton()
            self._toggle_btn.setText(f"Show all {len(self._sorted_av)} engines ▾")
            self._toggle_btn.setStyleSheet(
                "color:#4a9eda; border:none; font-size:11px; padding:4px 8px;"
            )
            self._toggle_btn.setCursor(QCursor(Qt.PointingHandCursor))
            self._toggle_btn.clicked.connect(self._toggle_av_list)
            cl.addWidget(self._toggle_btn)

        self._add_section(layout, "AV Detections", content)

    def _populate_av_table(self, count: int):
        results = self._sorted_av[:count]
        self._av_table.setRowCount(len(results))

        for i, av in enumerate(results):
            ei = QTableWidgetItem(av.engine_name)
            ei.setForeground(QColor(VTColors.TEXT_SECONDARY))
            ei.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            self._av_table.setItem(i, 0, ei)

            display = av.result or av.category.replace("-", " ").capitalize()
            ri = QTableWidgetItem(display)
            ri.setForeground(QColor(VTColors.for_category(av.category)))
            f = ri.font()
            f.setBold(av.category == "malicious")
            ri.setFont(f)
            ri.setTextAlignment(Qt.AlignCenter)
            self._av_table.setItem(i, 1, ri)

        rh = self._av_table.verticalHeader().defaultSectionSize()
        hh = self._av_table.horizontalHeader().height()
        self._av_table.setFixedHeight(hh + rh * len(results) + 4)

    def _toggle_av_list(self):
        if self._all_results_visible:
            self._populate_av_table(self.AV_PAGE_SIZE)
            self._toggle_btn.setText(f"Show all {len(self._sorted_av)} engines ▾")
        else:
            self._populate_av_table(len(self._sorted_av))
            self._toggle_btn.setText("Show less ▴")
        self._all_results_visible = not self._all_results_visible