import logging
from ..models import VTFileSummary
from PySide6.QtCore import QThread, Signal

class FetchReportTask(QThread):
    finished = Signal(int, object, str)

    def __init__(self, client, file_hash: str, parent=None):
        super().__init__(parent)
        self._client = client
        self._hash = file_hash

    def run(self):
        try:
            response = self._client.get_file(self._hash)
            if response.status_code == 200:
                attrs = response.json().get("data", {}).get("attributes", {})
                summary = VTFileSummary.from_api(attrs)
                self.finished.emit(200, summary, "")
            elif response.status_code == 404:
                self.finished.emit(404, None, "File not found on VirusTotal")
            else:
                self.finished.emit(response.status_code, None,
                                   f"API error (HTTP {response.status_code})")
        except Exception as e:
            logging.error(f"[VT] FetchReportWorker error: {e}")
            self.finished.emit(0, None, str(e))

