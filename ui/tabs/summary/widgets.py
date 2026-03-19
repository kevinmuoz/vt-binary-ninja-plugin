from PySide6.QtCore import Qt, QRect, QSize, QPoint
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import (
    QLabel,
    QLayout,
    QWidget,
)
from ....virustotal.models import AnalysisStats

class VTColors:
    # Verdict or category
    MALICIOUS    = "#E24B4A"
    SUSPICIOUS   = "#e67e22"
    HARMLESS     = "#639922"
    UNDETECTED   = "#444444"
    TIMEOUT      = "#666666"
    UNSUPPORTED  = "#555555"
    UNKNOWN      = "#888888"

    # Community score
    SCORE_NEG    = "#E24B4A"   # negative reputation
    SCORE_POS    = "#639922"   # positive reputation
    SCORE_ZERO   = "#888888"   # neutral

    # Threat label
    THREAT       = "#e07b3a"

    # UI chrome
    TEXT_PRIMARY   = "#d4d4d4"
    TEXT_SECONDARY = "#aaa"
    TEXT_MUTED     = "#666"
    TEXT_DIM       = "#555"
    SECTION_BORDER = "#333"
    DONUT_BG       = "#2a2a2a"
    DONUT_HOLE     = "#1e1e1e"
    TAG_BG         = "rgba(80, 80, 90, 0.5)"

    @classmethod
    def for_category(cls, category: str) -> str:
        return {
            "malicious":         cls.MALICIOUS,
            "suspicious":        cls.SUSPICIOUS,
            "harmless":          cls.HARMLESS,
            "timeout":           cls.TIMEOUT,
            "confirmed-timeout": cls.TIMEOUT,
            "failure":           cls.TIMEOUT,
            "type-unsupported":  cls.UNSUPPORTED,
        }.get(category, cls.UNKNOWN)

    @classmethod
    def for_verdict(cls, verdict: str) -> str:
        return {
            "malicious":  cls.MALICIOUS,
            "suspicious": cls.SUSPICIOUS,
        }.get(verdict, cls.HARMLESS)

    @classmethod
    def for_score(cls, reputation: int) -> str:
        if reputation < 0:
            return cls.SCORE_NEG
        if reputation > 0:
            return cls.SCORE_POS
        return cls.SCORE_ZERO

class FlowLayout(QLayout):
    """
    A wrapping flow layout that places child widgets left-to-right,
    wrapping to the next row when the available width is exceeded.

    Parameters:
    h_spacing : int
        Horizontal gap between items in the same row.
    v_spacing : int
        Vertical gap between rows.
    """

    def __init__(self, parent=None, h_spacing: int = 4, v_spacing: int = 4):
        super().__init__(parent)
        self._h = h_spacing
        self._v = v_spacing
        self._items: list = []

    # QLayout interface
    def addItem(self, item):
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, i: int):
        return self._items[i] if 0 <= i < len(self._items) else None

    def takeAt(self, i: int):
        return self._items.pop(i) if 0 <= i < len(self._items) else None

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        # Dry-run of the layout algorithm to compute the required height
        return self._lay(QRect(0, 0, width, 0), test=True)

    def setGeometry(self, rect: QRect):
        super().setGeometry(rect)
        self._lay(rect, test=False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        s = QSize()
        for it in self._items:
            s = s.expandedTo(it.minimumSize())
        m = self.contentsMargins()
        return s + QSize(m.left() + m.right(), m.top() + m.bottom())

    def _lay(self, rect: QRect, test: bool) -> int:
        """
        Core layout pass, shared by the geometry-setting path and the
        height-for-width estimation path.

        Parameters:
        rect : QRect
            The bounding rectangle available for layout
        test : bool
            When True, only compute and return the required height without
            actually moving any widgets (used by heightForWidth)

        Returns:
        int
            The total height consumed by all rows.
        """
        m = self.contentsMargins()
        # Effective area after subtracting margins
        effective = rect.adjusted(m.left(), m.top(), -m.right(), -m.bottom())

        x = effective.x()   # horizontal cursor
        y = effective.y()   # top of the current row
        row_height = 0      # tallest item seen in the current row

        for item in self._items:
            sz = item.sizeHint()
            next_x = x + sz.width() + self._h

            # If the item overflows the row (and the row is non-empty), then wrap
            if next_x - self._h > effective.right() + 1 and row_height > 0:
                x = effective.x()
                y += row_height + self._v
                row_height = 0
                next_x = x + sz.width() + self._h

            if not test:
                item.setGeometry(QRect(QPoint(x, y), sz))

            x = next_x
            row_height = max(row_height, sz.height())

        # Bottom edge of the last row, relative to rect.y(), plus bottom margin
        return y + row_height - rect.y() + m.bottom()


class TagPill(QLabel):
    """Compact rounded badge used to display file tags"""

    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setFont(QFont(self.font().family(), 9))
        self.setStyleSheet(
            f"background: {VTColors.TAG_BG}; color: {VTColors.TEXT_SECONDARY};"
            "border-radius:4px; padding:2px 8px; font-weight:500;"
        )


class DetectionDonut(QWidget):
    """Donut chart showing the malicious / clean / undetected breakdown."""

    def __init__(self, stats: AnalysisStats, parent=None):
        super().__init__(parent)
        self._stats = stats
        self.setFixedSize(100, 100)

    def paintEvent(self, event):
        s = self._stats
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        ring, margin = 9, 3
        outer_rect = self.rect().adjusted(margin, margin, -margin, -margin)
        inner_rect = self.rect().adjusted(
            margin + ring, margin + ring, -margin - ring, -margin - ring
        )

        # Background circle
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(VTColors.DONUT_BG))
        p.drawEllipse(outer_rect)

        # Verdict segments, starting from 12 o'clock (90°).
        # Qt angles are in 1/16th of a degree; positive = counter-clockwise.
        total = max(s.total_scanned, 1)
        start_angle = 90 * 16
        for count, color in [
            (s.malicious,  VTColors.MALICIOUS),
            (s.suspicious, VTColors.SUSPICIOUS),
            (s.harmless,   VTColors.HARMLESS),
            (s.undetected, VTColors.UNDETECTED),
        ]:
            if count <= 0:
                continue
            span = int(round(count / total * 360 * 16))
            p.setBrush(QColor(color))
            p.drawPie(outer_rect, start_angle, -span)
            start_angle -= span

        # Hollow centre
        p.setBrush(QColor(VTColors.DONUT_HOLE))
        p.drawEllipse(inner_rect)

        # Score text: "malicious / total"
        p.setPen(QColor(VTColors.TEXT_PRIMARY))
        p.setFont(QFont(self.font().family(), 13, QFont.Bold))
        p.drawText(
            self.rect().adjusted(0, -7, 0, 0),
            Qt.AlignCenter,
            f"{s.malicious}/{s.total_scanned}",
        )

        # Verdict label below the score
        p.setPen(QColor(VTColors.for_verdict(s.verdict)))
        p.setFont(QFont(self.font().family(), 8))
        p.drawText(
            self.rect().adjusted(0, 14, 0, 0),
            Qt.AlignCenter,
            s.verdict,
        )
        p.end()