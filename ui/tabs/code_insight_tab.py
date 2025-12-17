from binaryninjaui import UIContext
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTextEdit,
    QPushButton,
    QComboBox,
    QFrame,
    QStackedWidget,
    QSizePolicy,    
    QSplitter,
)
from PySide6.QtGui import QPixmap
from PySide6.QtCore import QTimer

import binaryninja as bn
import logging
import json
import base64
import textwrap

from ...core.vt_settings import settings
from ...virustotal.ci_notebook import CI_Notebook
from ...virustotal.codeinsight import QueryCodeInsight

VT_LOGO_RESOURCE = ":vtlogo/vt_logo.png"

class CodeInsightTab(QWidget):
    """Code Insight analysis tab."""

    PAGE_NO_API_KEY = 0
    PAGE_MAIN = 1

    SUBTITLE_DEFAULT = "In the Binary View, right-click a function and select ‘Ask Code Insight’ to start analysis."
    SUBTITLE_ACTIVE = "AI-powered function analysis"

    def __init__(self, parent: QWidget, bv: bn.BinaryView):
        super().__init__(parent)
        self.bv = bv
        self._destroyed = False

        # Data structures
        self.analyses = {}  # func_addr (int) -> analysis_data (dict)
        self.ci_notebook = CI_Notebook()
        self.current_func_addr = None
        self.current_task = None  # Track ongoing task
        self.pending_tasks = {}
        
        # Track destruction
        self.destroyed.connect(self._on_destroyed)

        # Build UI
        self._build_ui()
        self._update_ui_state()

    def _on_destroyed(self):
        self._destroyed = True

    def _is_alive(self) -> bool:
        if self._destroyed:
            return False
        try:
            _ = self.isVisible()
            return True
        except Exception:
            self._destroyed = True
            return False

    def _build_ui(self):
        """Build the UI with stacked pages."""
        self.stack = QStackedWidget()

        # Page 0: No API key
        self.stack.addWidget(self._create_no_api_page())

        # Page 1: Main UI
        self.stack.addWidget(self._create_main_page())

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.stack)
        self._apply_style()


    def _create_no_api_page(self) -> QWidget:
        """Create API key required page."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 40, 20, 40)

        layout.addStretch(1)

        # Logo
        logo = QLabel()
        pix = QPixmap(VT_LOGO_RESOURCE)
        if not pix.isNull():
            logo.setPixmap(pix.scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo)

        layout.addSpacing(24)

        # Title
        title = QLabel("API Key Required")
        title.setAlignment(Qt.AlignCenter)
        font = title.font()
        font.setPointSize(14)
        font.setBold(True)
        title.setFont(font)
        layout.addWidget(title)

        layout.addSpacing(16)

        # Message
        msg = QLabel(
            "<b>Code Insight</b> requires a VirusTotal API key.<br><br>"
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

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        btn_refresh = QPushButton("Refresh")
        btn_refresh.setMinimumHeight(32)
        btn_refresh.setMinimumWidth(100)
        btn_refresh.clicked.connect(self._update_ui_state)

        btn_settings = QPushButton("Open Settings")
        btn_settings.setMinimumHeight(32)
        btn_settings.setMinimumWidth(120)
        btn_settings.clicked.connect(self._open_settings)

        btn_layout.addWidget(btn_refresh)
        btn_layout.addSpacing(12)
        btn_layout.addWidget(btn_settings)
        btn_layout.addStretch()

        layout.addLayout(btn_layout)
        layout.addStretch(1)

        return page

    def _create_main_page(self) -> QWidget:
        """Create main Code Insight page."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # HEADER SECTION - Compact: Logo + Title + Function Metadata
        header_layout = QHBoxLayout()
        header_layout.setSpacing(10)

        # Logo (compact)
        self.logoLabel = QLabel()
        self.logoLabel.setAlignment(Qt.AlignCenter)
        self.logoLabel.setFixedSize(32, 32)

        pix = QPixmap(VT_LOGO_RESOURCE)
        if not pix.isNull():
            scaled_pix = pix.scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logoLabel.setPixmap(scaled_pix)

        header_layout.addWidget(self.logoLabel)

        # Left side: Title + subtitle (dynamic)
        title_layout = QVBoxLayout()
        title_layout.setSpacing(1)
        title_layout.setContentsMargins(0, 0, 0, 0)

        title_label = QLabel("Code Insight Notebook")
        title_font = title_label.font()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title_label.setFont(title_font)

        self.subtitleLabel = QLabel(self.SUBTITLE_DEFAULT)
        subtitle_font = self.subtitleLabel.font()
        subtitle_font.setPointSize(10)
        self.subtitleLabel.setFont(subtitle_font)
        self.subtitleLabel.setStyleSheet("color: rgba(255,255,255,0.5);")
        self.subtitleLabel.setWordWrap(True)

        title_layout.addWidget(title_label)
        title_layout.addWidget(self.subtitleLabel)

        header_layout.addLayout(title_layout, 1)

        # Right side: Function metadata (clickable to navigate) - only visible when a function selected
        self.metaWidget = QWidget()
        meta_layout = QVBoxLayout(self.metaWidget)
        meta_layout.setSpacing(1)
        meta_layout.setContentsMargins(0, 0, 0, 0)
        meta_layout.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.lblFunctionName = QLabel("")
        func_name_font = self.lblFunctionName.font()
        func_name_font.setPointSize(10)
        func_name_font.setBold(True)
        self.lblFunctionName.setFont(func_name_font)
        self.lblFunctionName.setAlignment(Qt.AlignRight)
        self.lblFunctionName.setCursor(Qt.PointingHandCursor)
        self.lblFunctionName.setToolTip("Click to navigate to this function")
        self.lblFunctionName.mousePressEvent = lambda e: self._on_go()
        self.lblFunctionName.setStyleSheet("""
            QLabel {
                color: rgba(255,255,255,0.95);
            }
            QLabel:hover {
                color: rgba(100,150,255,1.0);
            }
        """)

        self.lblFunctionMeta = QLabel("")
        meta_font = self.lblFunctionMeta.font()
        meta_font.setPointSize(8)
        self.lblFunctionMeta.setFont(meta_font)
        self.lblFunctionMeta.setAlignment(Qt.AlignRight)
        self.lblFunctionMeta.setStyleSheet("color: rgba(255,255,255,0.45);")

        meta_layout.addWidget(self.lblFunctionName)
        meta_layout.addWidget(self.lblFunctionMeta)

        self.metaWidget.setVisible(False)
        header_layout.addWidget(self.metaWidget)

        layout.addLayout(header_layout)
        layout.addSpacing(6)

        # Separator
        separator1 = QFrame()
        separator1.setFrameShape(QFrame.HLine)
        separator1.setFrameShadow(QFrame.Plain)
        separator1.setStyleSheet("background: rgba(255,255,255,0.1); max-height: 1px;")
        layout.addWidget(separator1)
        layout.addSpacing(6)

        # FUNCTION SELECTOR
        func_layout = QHBoxLayout()
        func_layout.setSpacing(8)

        func_label = QLabel("Function:")
        func_font = func_label.font()
        func_font.setBold(True)
        func_label.setFont(func_font)

        self.funcCombo = QComboBox()
        self.funcCombo.setMinimumHeight(28)
        self.funcCombo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        func_layout.addWidget(func_label)
        func_layout.addWidget(self.funcCombo, 1)

        layout.addLayout(func_layout)
        layout.addSpacing(6)

        # AI SUMMARY & DETAILED ANALYSIS
        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)

        # AI Summary
        summary_widget = QWidget()
        summary_layout = QVBoxLayout(summary_widget)
        summary_layout.setContentsMargins(0, 0, 0, 0)
        summary_layout.setSpacing(4)

        lblSummary = QLabel("AI Summary")
        font_summary = lblSummary.font()
        font_summary.setBold(True)
        font_summary.setPointSize(12)
        lblSummary.setFont(font_summary)

        self.txtSummary = QTextEdit()
        self.txtSummary.setPlaceholderText("Short summary of the function…")

        summary_layout.addWidget(lblSummary)
        summary_layout.addWidget(self.txtSummary, 1)

        splitter.addWidget(summary_widget)

        # Detailed Analysis
        desc_widget = QWidget()
        desc_layout = QVBoxLayout(desc_widget)
        desc_layout.setContentsMargins(0, 0, 0, 0)
        desc_layout.setSpacing(4)

        lblDesc = QLabel("Detailed Analysis")
        font_desc = lblDesc.font()
        font_desc.setBold(True)
        font_desc.setPointSize(12)
        lblDesc.setFont(font_desc)

        self.txtDescription = QTextEdit()
        self.txtDescription.setPlaceholderText("Detailed analysis of the function behavior…")

        desc_layout.addWidget(lblDesc)
        desc_layout.addWidget(self.txtDescription, 1)

        splitter.addWidget(desc_widget)

        # Default sizes (1:2 ratio)
        splitter.setSizes([120, 240])

        layout.addWidget(splitter, 1)
        layout.addSpacing(6)

        eval_layout = QHBoxLayout()
        eval_layout.setContentsMargins(0, 0, 0, 0)
        eval_layout.setSpacing(6)

        eval_label = QLabel(" Review analysis: ")

        eval_font = eval_label.font()
        eval_font.setBold(True)
        eval_font.setPointSize(12)
        eval_label.setFont(eval_font)

        eval_layout.addWidget(eval_label)

        eval_layout.addStretch()

        self.btnAccept = QPushButton("Accept")
        self.btnAccept.setMinimumHeight(26)
        self.btnAccept.clicked.connect(self._on_accept)
        self.btnAccept.setEnabled(False)
        self.btnAccept.setToolTip(
            "<b>Accept Analysis</b><br>"
            "Save this analysis to the notebook.<br>"
            "Accepted functions provide context for future analyses."
        )
        self.btnAccept.setStyleSheet("""
            QPushButton { 
                background: rgba(60,180,75,0.2); 
                border-color: rgba(60,180,75,0.4);
                padding: 4px 12px;
            }
            QPushButton:hover { 
                background: rgba(60,180,75,0.3); 
                border-color: rgba(60,180,75,0.6);
            }
            QPushButton:disabled {
                background: rgba(0,0,0,0.18);
                border-color: rgba(255,255,255,0.06);
            }
        """)

        self.btnDiscard = QPushButton("Discard")
        self.btnDiscard.setMinimumHeight(26)
        self.btnDiscard.clicked.connect(self._on_discard)
        self.btnDiscard.setEnabled(False)
        self.btnDiscard.setToolTip(
            "<b>Discard Analysis</b><br>"
            "Remove this function from the notebook."
        )
        self.btnDiscard.setStyleSheet("""
            QPushButton { 
                background: rgba(220,50,50,0.2); 
                border-color: rgba(220,50,50,0.4);
                padding: 4px 12px;
            }
            QPushButton:hover { 
                background: rgba(220,50,50,0.3); 
                border-color: rgba(220,50,50,0.6);
            }
            QPushButton:disabled {
                background: rgba(0,0,0,0.18);
                border-color: rgba(255,255,255,0.06);
            }
        """)

        self.btnRefresh = QPushButton("Refresh")
        self.btnRefresh.setMinimumHeight(26)
        self.btnRefresh.clicked.connect(self._on_refresh)
        self.btnRefresh.setEnabled(False)
        self.btnRefresh.setToolTip(
            "<b>Refresh Analysis</b><br>"
            "Re-analyze this function with Code Insight."
        )
        self.btnRefresh.setStyleSheet("""
            QPushButton { 
                background: rgba(100,150,255,0.2); 
                border-color: rgba(100,150,255,0.4);
                padding: 4px 12px;
            }
            QPushButton:hover { 
                background: rgba(100,150,255,0.3); 
                border-color: rgba(100,150,255,0.6);
            }
            QPushButton:disabled {
                background: rgba(0,0,0,0.18);
                border-color: rgba(255,255,255,0.06);
            }
        """)

        eval_layout.addWidget(self.btnAccept)
        eval_layout.addWidget(self.btnDiscard)
        eval_layout.addWidget(self.btnRefresh)

        layout.addLayout(eval_layout)
        layout.addSpacing(6)

        # Separator
        separator2 = QFrame()
        separator2.setFrameShape(QFrame.HLine)
        separator2.setFrameShadow(QFrame.Plain)
        separator2.setStyleSheet("background: rgba(255,255,255,0.1); max-height: 1px;")
        layout.addWidget(separator2)
        layout.addSpacing(6)

        # UTILITY ACTIONS (Footer)
        actions_layout = QHBoxLayout()
        actions_layout.setSpacing(6)

        self.btnAutocomment = QPushButton(" Apply as Comments ")
        self.btnAutocomment.setMinimumHeight(26)
        self.btnAutocomment.clicked.connect(self._on_autocomment)
        self.btnAutocomment.setEnabled(False)
        self.btnAutocomment.setToolTip(
            "<b>Apply as Comments</b><br>"
            "Add Code Insight summaries as function comments<br>"
            "for all accepted analyses."
        )

        self.btnLoad = QPushButton(" Load ")
        self.btnLoad.setMinimumHeight(26)
        self.btnLoad.clicked.connect(self._on_load)
        self.btnLoad.setToolTip(
            "<b>Load Notebook</b><br>"
            "Import a previously exported Code Insight notebook (JSON).<br>"
            "This will replace the current notebook."
        )

        self.btnExport = QPushButton(" Export ")
        self.btnExport.setMinimumHeight(26)
        self.btnExport.clicked.connect(self._on_export)
        self.btnExport.setEnabled(False)
        self.btnExport.setToolTip(
            "<b>Export Notebook</b><br>"
            "Save the current notebook to a JSON file.<br>"
            "Can be imported later or shared with others."
        )

        actions_layout.addWidget(self.btnAutocomment)
        actions_layout.addStretch()
        actions_layout.addWidget(self.btnLoad)
        actions_layout.addWidget(self.btnExport)

        layout.addLayout(actions_layout)

        # Internal signals
        self.funcCombo.currentIndexChanged.connect(self._on_function_selected)
        self.txtSummary.textChanged.connect(self._on_summary_changed)
        self.txtDescription.textChanged.connect(self._on_description_changed)

        return page

    def _update_header_metadata(self, func_name: str, address: int, code_type: str):
        """Update the header metadata labels when a function is selected."""
        self.lblFunctionName.setText(func_name)
        self.lblFunctionMeta.setText(f"0x{address:x} • {code_type}")
        self.metaWidget.setVisible(True)
        self.subtitleLabel.setText(self.SUBTITLE_ACTIVE)

    def _clear_header_metadata(self):
        """Clear header metadata to default state."""
        self.lblFunctionName.setText("")
        self.lblFunctionMeta.setText("")
        self.metaWidget.setVisible(False)
        self.subtitleLabel.setText(self.SUBTITLE_DEFAULT)
    
    def _has_api_key(self) -> bool:
        """Check if API key is configured."""
        try:
            return settings.get_api_key().strip() != ""
        except Exception:
            return False

    def _update_ui_state(self):
        """Update UI based on API key state."""
        if not self._is_alive():
            return

        if self._has_api_key():
            self.stack.setCurrentIndex(self.PAGE_MAIN)
        else:
            self.stack.setCurrentIndex(self.PAGE_NO_API_KEY)

    def _open_settings(self):
        """Open Binary Ninja settings."""
        try:
            ctx = UIContext.activeContext()
            if ctx:
                handler = ctx.contentActionHandler()
                if handler:
                    handler.executeAction("Settings")
        except Exception:
            pass

    # Analysis workflow methods

    def start_analysis(self, func: bn.Function, code: str, view_type: str):
        """Start Code Insight analysis for a function."""
        if not self._is_alive():
            return

        func_addr = func.start
        func_name = func.name

        logging.debug(f"[VT] Starting Code Insight analysis for {func_name} @ 0x{func_addr:x}")

        # Add pending analysis entry
        self._add_pending_analysis(func_addr, func_name, view_type, code)

        # Create and start the background task
        try:
            api_key = settings.get_api_key()
            
            task = QueryCodeInsight(
                api_key=api_key,
                code=code,
                use_codetype=view_type,
                ci_notebook=self.ci_notebook
            )

            # Store task reference
            self.pending_tasks[func_addr] = task

            # Start the task
            task.start()

            # Start polling for completion
            self._poll_task_completion(func_addr)

            logging.debug(f"[VT] QueryCodeInsight task started for 0x{func_addr:x}")

        except Exception as e:
            logging.error(f"[VT] Failed to start analysis task: {e}")
            self._update_analysis_result(
                func_addr,
                result=None,
                error_msg=f"Failed to start analysis: {str(e)}"
            )

    def _poll_task_completion(self, func_addr: int):
        """Poll for task completion using QTimer."""
        if not self._is_alive():
            return
        
        task = self.pending_tasks.get(func_addr)
        if not task:
            return
        
        if task.finished:
            # Task completed, process result
            self._on_analysis_complete(task, func_addr)
            # Remove from pending
            self.pending_tasks.pop(func_addr, None)
        else:
            # Not finished yet, check again in 500ms
            QTimer.singleShot(500, lambda: self._poll_task_completion(func_addr))

    def _on_refresh(self):
        """Handle Refresh button - Re-analyze current function."""
        if not self._is_alive() or self.current_func_addr is None:
            return

        analysis = self.analyses.get(self.current_func_addr)
        if not analysis:
            return

        logging.debug(f"[VT] Refreshing analysis for 0x{self.current_func_addr:x}")

        # Decode the stored code
        try:
            b64code = analysis['b64code']
            code = base64.urlsafe_b64decode(b64code).decode('utf-8')
        except Exception as e:
            logging.error(f"[VT] Failed to decode stored code: {e}")
            bn.show_message_box(
                "VirusTotal Code Insight",
                "Failed to refresh: Could not decode stored code",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.ErrorIcon,
            )
            return

        # Reset analysis to pending
        analysis['status'] = 'pending'
        analysis['summary'] = None
        analysis['description'] = None
        
        self._display_current_analysis()

        # Create new task
        try:
            api_key = settings.get_api_key()
            
            task = QueryCodeInsight(
                api_key=api_key,
                code=code,
                use_codetype=analysis['code_type'],
                ci_notebook=self.ci_notebook
            )

            self.pending_tasks[self.current_func_addr] = task
            task.start()
            
            # Start polling
            self._poll_task_completion(self.current_func_addr)

            logging.debug(f"[VT] Refresh task started for 0x{self.current_func_addr:x}")

        except Exception as e:
            logging.error(f"[VT] Failed to start refresh task: {e}")
            self._update_analysis_result(
                self.current_func_addr,
                result=None,
                error_msg=f"Failed to refresh: {str(e)}"
            )

    def _add_pending_analysis(self, func_addr: int, func_name: str, code_type: str, code: str):
        """Add a pending analysis entry to the UI."""
        if not self._is_alive():
            return

        # Encode the code for storage
        b64code = base64.urlsafe_b64encode(code.encode('utf-8')).decode('ascii')

        # Create pending analysis entry
        self.analyses[func_addr] = {
            'func_name': func_name,
            'func_addr': func_addr,
            'code_type': code_type,
            'b64code': b64code,
            'summary': None,
            'description': None,
            'expected_summary': None,
            'expected_description': None,
            'status': 'pending',
        }

        # Add to combo if not already there
        addr_hex = f"0x{func_addr:x}"
        existing_index = self.funcCombo.findText(addr_hex)
        
        if existing_index == -1:
            # Add empty item if this is the first
            if self.funcCombo.count() == 0:
                self.funcCombo.addItem("")
            
            self.funcCombo.addItem(addr_hex)
            logging.debug(f"[VT] Added {addr_hex} to function combo")
            
            # Select the newly added item
            new_index = self.funcCombo.findText(addr_hex)
            if new_index != -1:
                self.funcCombo.blockSignals(True)
                self.funcCombo.setCurrentIndex(new_index)
                self.funcCombo.blockSignals(False)
        else:
            self.funcCombo.blockSignals(True)
            self.funcCombo.setCurrentIndex(existing_index)
            self.funcCombo.blockSignals(False)

        # Update UI to show this function
        self.current_func_addr = func_addr
        self._display_current_analysis()

    def _on_analysis_complete(self, task: QueryCodeInsight, func_addr: int):
        """Callback when QueryCodeInsight task finishes."""
        if not self._is_alive():
            return

        logging.debug(f"[VT] Analysis complete for 0x{func_addr:x}")

        error_msg = task.get_error_msg()
        
        if error_msg:
            logging.error(f"[VT] Code Insight error: {error_msg}")
            self._update_analysis_result(func_addr, result=None, error_msg=error_msg)
            
            bn.show_message_box(
                "VirusTotal Code Insight",
                f"Analysis failed:\n\n{error_msg}",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.ErrorIcon,
            )
        else:
            result_bytes = task.get_result()
            
            if result_bytes:
                try:
                    result_json = json.loads(result_bytes)
                    logging.debug(f"[VT] Analysis result: {result_json}")
                    self._update_analysis_result(func_addr, result=result_json, error_msg=None)
                except Exception as e:
                    logging.error(f"[VT] Failed to parse analysis result: {e}")
                    self._update_analysis_result(
                        func_addr,
                        result=None,
                        error_msg=f"Failed to parse result: {str(e)}"
                    )
            else:
                logging.error("[VT] No result returned from task")
                self._update_analysis_result(
                    func_addr,
                    result=None,
                    error_msg="No result returned from Code Insight"
                )

        self.current_task = None

    def _update_analysis_result(self, func_addr: int, result: dict, error_msg: str):
        """Update analysis entry with result or error."""
        if not self._is_alive():
            return

        if func_addr not in self.analyses:
            logging.warning(f"[VT] Tried to update non-existent analysis for 0x{func_addr:x}")
            return

        analysis = self.analyses[func_addr]

        if result:
            analysis['summary'] = result.get('summary', '')
            analysis['description'] = result.get('description', '')
            analysis['status'] = 'completed'
            logging.debug(f"[VT] Updated analysis for 0x{func_addr:x} with result")
        else:
            analysis['summary'] = f"Error: {error_msg}"
            analysis['description'] = "Analysis failed. Please try again."
            analysis['status'] = 'error'
            logging.debug(f"[VT] Updated analysis for 0x{func_addr:x} with error")

        if self.current_func_addr == func_addr:
            self._display_current_analysis()

    def _display_current_analysis(self):
        """Display the current analysis in the UI."""
        if not self._is_alive() or self.current_func_addr is None:
            return

        analysis = self.analyses.get(self.current_func_addr)
        if not analysis:
            self._clear_details()
            return

        # Update header metadata
        self._update_header_metadata(
            func_name=analysis['func_name'],
            address=analysis['func_addr'],
            code_type=analysis['code_type']
        )

        status = analysis['status']

        if status == 'pending':
            self.txtSummary.setPlainText("Running Code Insight…")
            self.txtDescription.setPlainText("Talking to VirusTotal, this may take a moment.")
            self._set_buttons_for_pending()

        elif status == 'completed':
            summary = analysis.get('expected_summary') or analysis.get('summary', '')
            description = analysis.get('expected_description') or analysis.get('description', '')
            
            self.txtSummary.blockSignals(True)
            self.txtDescription.blockSignals(True)
            
            self.txtSummary.setPlainText(summary)
            self.txtDescription.setPlainText(description)
            
            self.txtSummary.blockSignals(False)
            self.txtDescription.blockSignals(False)
            
            self._set_buttons_for_completed()
            
        elif status == 'error':
            self.txtSummary.setPlainText(analysis.get('summary', 'Error'))
            self.txtDescription.setPlainText(analysis.get('description', 'Analysis failed'))
            self._set_buttons_for_error()

    def _set_buttons_for_pending(self):
        """Set button states for pending analysis."""
        self.btnAccept.setEnabled(False)
        self.btnDiscard.setEnabled(False)
        self.btnRefresh.setEnabled(False)

    def _set_buttons_for_completed(self):
        """Set button states for completed analysis."""
        self.btnAccept.setEnabled(True)
        self.btnDiscard.setEnabled(True)
        self.btnRefresh.setEnabled(True)

    def _set_buttons_for_error(self):
        """Set button states for error."""
        self.btnAccept.setEnabled(False)
        self.btnDiscard.setEnabled(True)
        self.btnRefresh.setEnabled(True)

    def _on_summary_changed(self):
        """Handle summary text change (user edit detection)."""
        if not self._is_alive() or self.current_func_addr is None:
            return

        analysis = self.analyses.get(self.current_func_addr)
        if not analysis or analysis['status'] != 'completed':
            return

        new_summary = self.txtSummary.toPlainText()
        original_summary = analysis.get('summary', '')

        if new_summary != original_summary:
            if not self.btnAccept.isEnabled():
                self.btnAccept.setEnabled(True)

    def _on_description_changed(self):
        """Handle description text change (user edit detection)."""
        if not self._is_alive() or self.current_func_addr is None:
            return

        analysis = self.analyses.get(self.current_func_addr)
        if not analysis or analysis['status'] != 'completed':
            return

        new_description = self.txtDescription.toPlainText()
        original_description = analysis.get('description', '')

        if new_description != original_description:
            if not self.btnAccept.isEnabled():
                self.btnAccept.setEnabled(True)

    def _on_function_selected(self, index: int):
        """Handle function selection change in combo."""
        if not self._is_alive() or index < 0:
            return

        addr_text = self.funcCombo.itemText(index)
        if not addr_text or addr_text == "":
            self._clear_details()
            return

        try:
            func_addr = int(addr_text, 16)
            
            if func_addr in self.analyses:
                self.current_func_addr = func_addr
                self._display_current_analysis()
            else:
                logging.warning(f"[VT] Selected address {addr_text} not in analyses")
                self._clear_details()
                
        except ValueError:
            logging.error(f"[VT] Failed to parse address from combo: {addr_text}")
            self._clear_details()

    def _clear_details(self) -> None:
        """Clear all detail fields."""
        self._clear_header_metadata()
        self.txtSummary.clear()
        self.txtDescription.clear()
        self.current_func_addr = None
        
        self.btnAccept.setEnabled(False)
        self.btnDiscard.setEnabled(False)
        self.btnRefresh.setEnabled(False)

    # Button handlers

    def _on_accept(self):
        """Handle Accept button - Save to notebook."""
        if not self._is_alive() or self.current_func_addr is None:
            return

        analysis = self.analyses.get(self.current_func_addr)
        if not analysis:
            return

        logging.debug(f"[VT] Accepting analysis for 0x{self.current_func_addr:x}")

        current_summary = self.txtSummary.toPlainText()
        current_description = self.txtDescription.toPlainText()
        
        original_summary = analysis.get('summary', '')
        original_description = analysis.get('description', '')
        
        expected_summary = None
        expected_description = None
        
        if current_summary != original_summary:
            expected_summary = current_summary
        
        if current_description != original_description:
            expected_description = current_description

        self.ci_notebook.add_page(
            func_name=analysis['func_name'],
            func_addr=f"0x{analysis['func_addr']:x}",
            code_type=analysis['code_type'],
            b64code=analysis['b64code'],
            summary=analysis['summary'],
            description=analysis['description'],
            expected_summary=expected_summary,
            expected_description=expected_description
        )

        analysis['expected_summary'] = expected_summary
        analysis['expected_description'] = expected_description

        self.btnAccept.setEnabled(False)

        if self.ci_notebook.get_total() > 0:
            self.btnExport.setEnabled(True)
            self.btnAutocomment.setEnabled(True)

        logging.info(f"[VT] Analysis accepted and saved to notebook (total: {self.ci_notebook.get_total()})")

    def _on_discard(self):
        """Handle Discard button - Remove from notebook and analyses."""
        if not self._is_alive() or self.current_func_addr is None:
            return

        addr_hex = f"0x{self.current_func_addr:x}"
        logging.debug(f"[VT] Discarding analysis for {addr_hex}")

        if self.ci_notebook.get_page(addr_hex):
            self.ci_notebook.discard_page(addr_hex)

        if self.current_func_addr in self.analyses:
            del self.analyses[self.current_func_addr]

        index = self.funcCombo.findText(addr_hex)
        if index != -1:
            self.funcCombo.removeItem(index)

        self._clear_details()

        if self.ci_notebook.get_total() == 0:
            self.btnExport.setEnabled(False)
            self.btnAutocomment.setEnabled(False)

        if self.funcCombo.count() > 1:
            self.funcCombo.setCurrentIndex(1)

    def _on_go(self):
        """Navigate to selected function in Binary Ninja."""
        if not self._is_alive() or self.current_func_addr is None:
            return

        if self.bv is None:
            return

        try:
            ctx = UIContext.activeContext()
            if ctx:
                vf = ctx.getCurrentViewFrame()
                if vf:
                    vf.navigate(self.bv, self.current_func_addr)
                    logging.debug(f"[VT] Navigated to 0x{self.current_func_addr:x}")
        except Exception as e:
            logging.error(f"[VT] Failed to navigate: {e}")

    def _on_autocomment(self):
        """Handle Autocomment button - Add comments to all functions in notebook."""
        if not self._is_alive():
            return

        n_funcs = self.ci_notebook.get_total()
        
        if n_funcs == 0:
            logging.debug("[VT] No functions in notebook to comment")
            return

        if self.bv is None:
            logging.error("[VT] No binary view available for commenting")
            bn.show_message_box(
                "VirusTotal Code Insight",
                "No binary view available.",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.ErrorIcon,
            )
            return

        logging.debug(f"[VT] Auto-commenting {n_funcs} functions")

        commented_count = 0
        skipped_count = 0

        for addr_hex in self.ci_notebook.get_functions():
            page = self.ci_notebook.get_page(addr_hex)
            
            if page.get('expected_summary'):
                summary = page['expected_summary']
            else:
                summary = page.get('summary', '')
            
            if not summary:
                logging.debug(f"[VT] No summary for function {addr_hex}, skipping")
                skipped_count += 1
                continue

            try:
                func_addr = int(addr_hex, 16)
            except ValueError:
                logging.warning(f"[VT] Invalid address: {addr_hex}")
                skipped_count += 1
                continue

            func = self.bv.get_function_at(func_addr)
            if not func:
                logging.warning(f"[VT] Function not found at {addr_hex}")
                skipped_count += 1
                continue

            wrapped_summary = textwrap.fill(summary, width=80)
            new_comment_block = f"[CodeInsight start]\n{wrapped_summary}\n[CodeInsight end]"

            current_comment = func.get_comment_at(func_addr) or ""

            start_marker = "[CodeInsight start]"
            end_marker = "[CodeInsight end]"
            start_pos = current_comment.find(start_marker)

            final_comment = ""
            
            if start_pos != -1:
                logging.debug(f"[VT] Updating existing Code Insight comment for {addr_hex}")
                end_pos = current_comment.find(end_marker, start_pos)
                
                if end_pos != -1:
                    before_block = current_comment[:start_pos]
                    after_block = current_comment[end_pos + len(end_marker):]
                    final_comment = before_block.rstrip() + '\n' + new_comment_block + '\n' + after_block.lstrip()
                else:
                    logging.warning(f"[VT] Malformed comment in {addr_hex}. Appending.")
                    final_comment = current_comment + '\n\n' + new_comment_block
            else:
                logging.debug(f"[VT] Adding new Code Insight comment for {addr_hex}")
                if current_comment:
                    final_comment = current_comment + '\n\n' + new_comment_block
                else:
                    final_comment = new_comment_block

            try:
                func.set_comment_at(func_addr, final_comment.strip())
                commented_count += 1
                logging.debug(f"[VT] Comment added/updated for {addr_hex}")
            except Exception as e:
                logging.error(f"[VT] Failed to set comment at {addr_hex}: {e}")
                skipped_count += 1

        message = f"Comments updated for {commented_count} function(s)."
        if skipped_count > 0:
            message += f"\n\nSkipped {skipped_count} function(s) (no summary or function not found)."

        bn.show_message_box(
            "VirusTotal Code Insight",
            message,
            bn.MessageBoxButtonSet.OKButtonSet,
            bn.MessageBoxIcon.InformationIcon,
        )

        logging.info(f"[VT] Auto-comment complete: {commented_count} updated, {skipped_count} skipped")

    def _on_load(self):
        """Handle Load button - Import notebook from JSON file."""
        if not self._is_alive():
            return

        if self.ci_notebook.get_total() > 0:
            result = bn.show_message_box(
                "VirusTotal Code Insight",
                "Importing a new Code Insight Notebook will replace the current one.\n\n"
                "Do you want to continue?",
                bn.MessageBoxButtonSet.YesNoButtonSet,
                bn.MessageBoxIcon.QuestionIcon,
            )
            if result != bn.MessageBoxButtonResult.YesButton:
                logging.debug("[VT Plugin] User cancelled the import of a new notebook")
                return

        filename = bn.get_open_filename_input("Select Code Insight notebook JSON", "*.json")
        if not filename:
            logging.debug("[VT Plugin] No file selected to import CI Notebook")
            return

        try:
            logging.debug("[VT Plugin] Loading CodeInsight Notebook file: %s", filename)
            with open(filename, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.ci_notebook.import_data(data)
            self._reload_notebook_to_ui()

            bn.show_message_box(
                "VirusTotal Code Insight",
                f"Successfully loaded notebook from:\n{filename}\n\n"
                f"Total functions: {self.ci_notebook.get_total()}",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.InformationIcon,
            )
            
            logging.info(f"[VT Plugin] Imported {self.ci_notebook.get_total()} functions from notebook")

        except json.JSONDecodeError as e:
            logging.error(f"[VT Plugin] Invalid JSON file: {e}")
            bn.show_message_box(
                "VirusTotal Code Insight",
                "Failed to load notebook:\n\nInvalid JSON format",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.ErrorIcon,
            )
        except Exception as e:
            logging.exception(f"[VT Plugin] ERROR importing file: {filename}")
            bn.show_message_box(
                "VirusTotal Code Insight",
                f"Failed to load notebook:\n\n{str(e)}",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.ErrorIcon,
            )

    def _reload_notebook_to_ui(self):
        """Reload the notebook contents into the UI."""
        if not self._is_alive():
            return

        logging.debug("[VT Plugin] Reloading notebook into UI")

        self.analyses.clear()
        self.funcCombo.clear()
        self._clear_details()

        self.funcCombo.addItem("")

        for addr_hex in self.ci_notebook.get_functions():
            page = self.ci_notebook.get_page(addr_hex)
            
            if not page:
                continue

            try:
                func_addr = int(addr_hex, 16)
            except ValueError:
                logging.warning(f"[VT Plugin] Invalid address in notebook: {addr_hex}")
                continue

            self.analyses[func_addr] = {
                'func_name': page.get('func_name', 'unknown'),
                'func_addr': func_addr,
                'code_type': page.get('code_type', 'disassembled'),
                'b64code': page.get('b64code', ''),
                'summary': page.get('summary', ''),
                'description': page.get('description', ''),
                'expected_summary': page.get('expected_summary'),
                'expected_description': page.get('expected_description'),
                'status': 'completed',
            }

            self.funcCombo.addItem(addr_hex)
            logging.debug(f"[VT Plugin] Added {addr_hex} to combo from notebook")

        if self.ci_notebook.get_total() > 0:
            self.funcCombo.setEnabled(True)
            self.btnExport.setEnabled(True)
            self.btnAutocomment.setEnabled(True)
            
            if self.funcCombo.count() > 1:
                self.funcCombo.setCurrentIndex(1)

        logging.info(f"[VT Plugin] Reloaded {self.ci_notebook.get_total()} functions into UI")

    def _on_export(self):
        """Export the current Code Insight notebook to a JSON file."""
        if not self._is_alive():
            return

        total = self.ci_notebook.get_total()
        if total == 0:
            bn.show_message_box(
                "VirusTotal Code Insight",
                "No functions in notebook to export.",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.WarningIcon,
            )
            return

        filename = bn.get_save_filename_input(
            "Save Code Insight notebook",
            "*.json",
            "codeinsight_notebook.json",
        )

        if not filename:
            logging.info("[VT Plugin] Export cancelled by user")
            return

        if not filename.endswith('.json'):
            filename += '.json'

        logging.info("[VT Plugin] Exporting notebook to: %s", filename)

        try:
            logging.debug("[VT Plugin] Exporting CodeInsight Notebook to file: %s", filename)
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.ci_notebook.show_pages(), f, indent=2)
            
            bn.show_message_box(
                "VirusTotal Code Insight",
                f"Successfully exported notebook to:\n{filename}\n\n"
                f"Total functions: {total}",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.InformationIcon,
            )
            
            logging.info(f"[VT Plugin] Exported {total} functions to {filename}")

        except Exception as e:
            logging.exception("[VT Plugin] ERROR saving file: %s", filename)
            bn.show_message_box(
                "VirusTotal Code Insight",
                f"Failed to export notebook:\n\n{str(e)}",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.ErrorIcon,
            )

    def _apply_style(self):
        self.setStyleSheet("""
        /* Tabs */
        QTabWidget::pane {
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 8px;
            background: rgba(0,0,0,0.18);
            margin-top: 4px;
        }
        QTabBar::tab {
            padding: 5px 10px;
            margin-right: 4px;
            border: 1px solid rgba(255,255,255,0.10);
            border-bottom: none;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            background: rgba(0,0,0,0.18);
            color: rgba(255,255,255,0.75);
            min-height: 20px;
        }
        QTabBar::tab:selected {
            background: rgba(0,0,0,0.35);
            color: rgba(255,255,255,0.95);
            border-color: rgba(255,255,255,0.16);
        }
        QTabBar::tab:hover {
            color: rgba(255,255,255,0.90);
            border-color: rgba(255,255,255,0.18);
        }

        /* Inputs */
        QLineEdit, QComboBox, QTextEdit {
            border: 1px solid rgba(255,255,255,0.10);
            border-radius: 6px;
            padding: 4px 6px;
            background: rgba(0,0,0,0.22);
            selection-background-color: rgba(120,140,255,0.35);
        }
        QLineEdit[readOnly="true"] {
            color: rgba(255,255,255,0.75);
            background: rgba(0,0,0,0.12);
        }

        /* Buttons */
        QPushButton {
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 6px;
            padding: 4px 8px;
            background: rgba(0,0,0,0.18);
        }
        QPushButton:hover { border-color: rgba(255,255,255,0.20); }
        QPushButton:disabled { color: rgba(255,255,255,0.35); border-color: rgba(255,255,255,0.06); }

        /* Separator */
        QFrame[frameShape="4"] {
            color: rgba(255,255,255,0.10);
            background: rgba(255,255,255,0.10);
            max-height: 1px;
        }
        """)