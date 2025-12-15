from binaryninjaui import UIContext
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QLabel,
    QMenu,
    QApplication,
)
from PySide6.QtGui import QAction

from ...virustotal import vtgrep
import binaryninja as bn
import logging

class VTGrepTab(QWidget):
    """String listing and VT Grep search tab."""

    COL_ADDR = 0
    COL_TYPE = 1
    COL_LEN = 2
    COL_VALUE = 3

    def __init__(self, parent, bv):
        super().__init__(parent)
        self.bv: bn.BinaryView = bv
        self._destroyed = False
        self._all_rows = []
        self._loading = False

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

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)

        # Title
        title = QLabel("Strings")
        title.setStyleSheet("font-weight: bold;")
        layout.addWidget(title)

        # Filter
        self.filterEdit = QLineEdit()
        self.filterEdit.setPlaceholderText("Search strings...")
        self.filterEdit.textChanged.connect(self._apply_filter)
        layout.addWidget(self.filterEdit)

        # Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Address", "Type", "Len", "Value"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_context_menu)
        self.table.cellDoubleClicked.connect(self._on_double_click)  # <-- Añadir esto
        layout.addWidget(self.table, 1)

        # Status
        self.status = QLabel("Open a file to list strings.")
        layout.addWidget(self.status)

    def schedule_reload(self, delay_ms: int = 300):
        """Schedule a reload of strings."""
        if not self._is_alive() or self._loading:
            return
        QTimer.singleShot(delay_ms, self._load_strings)

    def refresh_strings(self):
        """Immediate refresh."""
        self.schedule_reload(0)

    def _load_strings(self):
        """Load strings from BinaryView."""
        if not self._is_alive():
            return

        if self.bv is None:
            self._all_rows = []
            self.table.setRowCount(0)
            self.status.setText("Open a file to list strings.")
            return

        self._loading = True
        self.status.setText("Loading strings...")

        try:
            strings = list(self.bv.get_strings())
            self._all_rows = []

            for s in strings:
                addr = s.start
                length = s.length
                stype = s.type
                type_name = (
                    stype.name
                    if hasattr(stype, "name")
                    else str(stype)
                    if stype
                    else ""
                )

                # Get raw value and sanitize for single-line display
                raw_value = s.value or ""
                # Replace newlines and tabs with spaces for table display
                display_value = (
                    raw_value.replace("\r\n", " ")
                    .replace("\n", " ")
                    .replace("\r", " ")
                    .replace("\t", " ")
                    .strip()
                )

                # Store both: display_value for table, raw_value for search/copy
                self._all_rows.append(
                    (addr, type_name, length, display_value, raw_value)
                )

            self._rebuild_table(self._all_rows)
            self.status.setText(f"{len(self._all_rows)} strings")

        except Exception as e:
            logging.error(f"[VT] Error loading strings: {e}")
            self.status.setText("Error loading strings.")

        finally:
            self._loading = False

    def _rebuild_table(self, rows):
        """Rebuild table with given rows."""
        if not self._is_alive():
            return

        self.table.setRowCount(len(rows))

        for i, row_data in enumerate(rows):
            addr, stype, length, display_value, raw_value = row_data

            self.table.setItem(i, self.COL_ADDR, QTableWidgetItem(f"0x{addr:x}"))
            self.table.setItem(i, self.COL_TYPE, QTableWidgetItem(stype))
            self.table.setItem(i, self.COL_LEN, QTableWidgetItem(str(length)))

            item = QTableWidgetItem(display_value)
            item.setToolTip(raw_value)
            item.setData(Qt.UserRole, raw_value)
            self.table.setItem(i, self.COL_VALUE, item)

    def _apply_filter(self, text: str):
        """Filter displayed strings."""
        if not self._is_alive() or self._loading:
            return

        needle = text.strip().lower()
        if not needle:
            self._rebuild_table(self._all_rows)
            self.status.setText(f"{len(self._all_rows)} strings")
        else:
            filtered = [
                r
                for r in self._all_rows
                if needle in r[3].lower() or needle in r[4].lower()
            ]
            self._rebuild_table(filtered)
            self.status.setText(f"{len(filtered)} strings (filtered)")

    def _on_context_menu(self, pos):
        if not self._is_alive():
            return

        item = self.table.itemAt(pos)
        if not item:
            return

        # Get all selected rows
        selected_rows = set(
            idx.row() for idx in self.table.selectionModel().selectedRows()
        )
        if not selected_rows:
            selected_rows = {item.row()}

        menu = QMenu(self.table)

        # Search on VirusTotal
        if len(selected_rows) == 1:
            act_search = QAction("Search on VirusTotal", self.table)
        else:
            act_search = QAction(
                f"Search {len(selected_rows)} Strings on VirusTotal", self.table
            )
        act_search.triggered.connect(lambda: self._search_on_vt(selected_rows))
        menu.addAction(act_search)

        menu.addSeparator()

        # Copy single value
        act_copy = QAction("Copy Value", self.table)
        act_copy.triggered.connect(lambda: self._copy_values(item.row()))
        menu.addAction(act_copy)

        # Copy all selected values
        if len(selected_rows) > 1:
            act_copy_all = QAction(f"Copy {len(selected_rows)} Values", self.table)
            act_copy_all.triggered.connect(lambda: self._copy_values(selected_rows))
            menu.addAction(act_copy_all)

        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def _copy_values(self, rows):
        """Copy one or multiple string values to clipboard."""
        if isinstance(rows, int):
            rows = {rows}

        values = []
        for row in sorted(rows):
            item = self.table.item(row, self.COL_VALUE)
            if item:
                raw_value = item.data(Qt.UserRole) or item.text()
                values.append(raw_value)
        if values:
            QApplication.clipboard().setText("\n".join(values))

    def _search_on_vt(self, rows):
        """Search selected strings on VirusTotal."""

        for row in sorted(rows):
            item = self.table.item(row, self.COL_VALUE)
            if not item:
                continue

            string_value = item.data(Qt.UserRole) or item.text()
            if not string_value:
                continue

            try:
                search_vt = vtgrep.VTGrepSearch(string=string_value)
                search_vt.search(wildcards=False)
            except Exception as e:
                logging.error(
                    f"[VT] VTGrepSearch failed for '{string_value[:30]}...': {e}"
                )

    def _on_double_click(self, row: int, column: int):
        """Navigate to string address on double click."""
        if not self._is_alive() or self.bv is None:
            return

        item = self.table.item(row, self.COL_ADDR)
        if not item:
            return

        try:
            # Parse address from hex string
            addr_str = item.text()
            addr = int(addr_str, 16)

            ctx = UIContext.activeContext()
            if ctx:
                vf = ctx.getCurrentViewFrame()
                if vf:
                    vf.navigate(self.bv, addr)
        except Exception as e:
            logging.error(f"[VT] Error navigating to string: {e}")
