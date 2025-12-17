from binaryninjaui import (
    SidebarWidget,
    SidebarWidgetType,
    UIActionHandler,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
)

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QVBoxLayout,
    QTabWidget,
    QStackedWidget,
    QWidget,
    QLabel,
)
from PySide6.QtGui import QPixmap, QImage, QPainter, QFont, QColor

from .resources import qt6logo # noqa: F401
from .tabs.vt_grep_tab import VTGrepTab
from .tabs.code_insight_tab import CodeInsightTab
import logging

VT_ICON_RESOURCE = ":vtlogo/vt_logo.png"

class VTSidebarWidget(SidebarWidget):
    """Main VirusTotal sidebar widget."""

    PAGE_NO_FILE = 0
    PAGE_MAIN = 1

    def __init__(self, name: str, frame, data):
        super().__init__(name)

        self.bv = data
        self._destroyed = False

        # Track destruction
        self.destroyed.connect(self._on_destroyed)

        # Action handler
        self._actionHandler = UIActionHandler()
        self._actionHandler.setupActionHandler(self)

        # Build UI
        self._build_ui()

        # Initial state
        self._update_page()

    def _on_destroyed(self):
        """Mark widget as destroyed to prevent access to dead Qt objects."""
        self._destroyed = True

    def _is_alive(self) -> bool:
        """Check if widget is still valid."""
        if self._destroyed:
            return False
        try:
            # Try to access a property - will fail if deleted
            _ = self.isVisible()
            return True
        except RuntimeError:
            self._destroyed = True
            return False

    def _build_ui(self):
        """Build the complete UI."""
        root = QVBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.stack = QStackedWidget()

        # Page 0: No file
        self.stack.addWidget(self._create_no_file_page())

        # Page 1: Main tabs
        self.stack.addWidget(self._create_main_page())

        root.addWidget(self.stack)
        self.setLayout(root)

    def _create_no_file_page(self) -> QWidget:
        """Create the 'no file open' placeholder page."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 40, 20, 40)

        layout.addStretch(1)

        # Logo
        logo = QLabel()
        pix = QPixmap(VT_ICON_RESOURCE)
        if not pix.isNull():
            logo.setPixmap(
                pix.scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            )
        logo.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo)

        layout.addSpacing(24)

        # Title
        title = QLabel("No File Open")
        title.setAlignment(Qt.AlignCenter)
        font = title.font()
        font.setPointSize(14)
        font.setBold(True)
        title.setFont(font)
        layout.addWidget(title)

        layout.addSpacing(16)

        # Message
        msg = QLabel(
            "The <b>VirusTotal Sidebar</b> requires an open file.<br><br>"
            "Open a binary file to analyze with<br>"
            "<b>Code Insight</b> and <b>VT Grep</b>."
        )
        msg.setWordWrap(True)
        msg.setAlignment(Qt.AlignCenter)
        msg.setTextFormat(Qt.RichText)
        layout.addWidget(msg)

        layout.addStretch(1)

        return page

    def _create_main_page(self) -> QWidget:
        """Create the main page with tabs."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.North)

        # Create tabs
        self.code_tab = CodeInsightTab(self, self.bv)
        self.tabs.addTab(self.code_tab, "Code Insight Notebook")

        self.vtgrep_tab = VTGrepTab(self, self.bv)
        self.tabs.addTab(self.vtgrep_tab, "VT Grep")

        layout.addWidget(self.tabs)
        return page

    def _update_page(self):
        """Switch to the appropriate page based on state."""
        if not self._is_alive():
            return

        if self.bv is None:
            self.stack.setCurrentIndex(self.PAGE_NO_FILE)
        else:
            self.stack.setCurrentIndex(self.PAGE_MAIN)

    def notifyOffsetChanged(self, offset):
        """Called when cursor position changes."""
        pass

    def notifyViewChanged(self, view_frame):
        """Called when view/file changes."""
        if not self._is_alive():
            return

        try:
            new_bv = view_frame.getCurrentBinaryView() if view_frame else None

            self.bv = new_bv

            # Update child tabs
            if hasattr(self, 'code_tab'):
                self.code_tab.bv = new_bv
                if hasattr(self.code_tab, '_update_ui_state'):
                    self.code_tab._update_ui_state()

            if hasattr(self, "vtgrep_tab"):
                self.vtgrep_tab.bv = new_bv
                if new_bv and hasattr(self.vtgrep_tab, "schedule_reload"):
                    self.vtgrep_tab.schedule_reload()

            self._update_page()

        except Exception as e:
            logging.error(f"[VT] Error in notifyViewChanged: {e}")

    def show_code_insight_tab(self):
        """Public method to switch to the Code Insight tab"""
        if hasattr(self, 'tabs') and hasattr(self, 'code_tab'):
            self.tabs.setCurrentWidget(self.code_tab)


class VTSidebarWidgetType(SidebarWidgetType):
    """Factory for creating VTSidebarWidget instances."""

    def __init__(self):
        # Load icon
        pix = QPixmap(VT_ICON_RESOURCE)
        if not pix.isNull():
            icon = pix.toImage()
        else:
            # Fallback icon
            icon = QImage(56, 56, QImage.Format_RGB32)
            icon.fill(0)
            p = QPainter()
            p.begin(icon)
            p.setFont(QFont("Open Sans", 30))
            p.setPen(QColor(255, 255, 255, 255))
            p.drawText(icon.rect(), Qt.AlignCenter, "VT")
            p.end()

        super().__init__(icon, "VirusTotal")

    def createWidget(self, frame, data):
        return VTSidebarWidget("VirusTotal", frame, data)

    def defaultLocation(self):
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        return SidebarContextSensitivity.SelfManagedSidebarContext
