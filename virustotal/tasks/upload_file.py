import logging
from PySide6.QtCore import QThread, Signal

class UploadFileTask(QThread):
    finished = Signal(bool, str)

    def __init__(self, client, file_path: str, parent=None):
        super().__init__(parent)
        self._client = client
        self._path = file_path

    def run(self):
        try:
            response = self._client.upload_file(self._path)
            if response.ok:
                self.finished.emit(True, "")
            else:
                self.finished.emit(False, f"Upload failed (HTTP {response.status_code})")
        except Exception as e:
            logging.error(f"[VT] UploadFileWorker error: {e}")
            self.finished.emit(False, str(e))