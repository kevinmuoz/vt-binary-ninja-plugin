import binaryninja as bn
import os
import logging
import hashlib
from .vtclient import VTClient


class CheckSample(bn.BackgroundTaskThread):
    """
    Background task to check and optionally upload a sample to VirusTotal.
    """

    def __init__(self, bv: bn.BinaryView, auto_upload: bool, api_key: str):
        self.bv = bv
        self.auto_upload = auto_upload
        self.api_key = api_key

        logging.debug(f"[VT Plugin] Init CheckSample for {bv.file.filename}")

        self.input_file = self.bv.file.filename
        self.file_hash = self.get_file_sha256(self.bv.file.filename)
        self.client = VTClient(api_key, user_agent="BN VT Plugin Upload")

        logging.debug(f"[VT Plugin] File SHA256: {self.file_hash}")

        super().__init__(
            initial_progress_text=f"Checking VT for{bv.file.filename}...",
            can_cancel=False,
        )

    def file_exists_on_disk(self) -> bool:
        """Check if the input file exists on disk."""
        return os.path.isfile(self.input_file)

    def get_file_sha256(self, filepath):
        """Get SHA256 hash of the file."""
        if not self.file_exists_on_disk():
            return None
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def check_file_missing_in_VT(self) -> bool:
        """Return True if the file is not available at VirusTotal."""

        if not self.api_key:
            logging.info("[VT Plugin] No API KEY is configured: skipping hash check.")
            return self.auto_upload

        try:
            response = self.client.get_file(self.file_hash)
        except Exception:
            self.progress = "Unable to connect to VirusTotal.com"
            logging.error("[VT Plugin] Unable to connect to VirusTotal.com")
            return False

        if response.status_code == 404:  # file not found in VirusTotal
            self.progress = "File not found on VirusTotal. Preparing upload..."
            return True

        if response.status_code == 200:
            self.progress = "File already available on VirusTotal."
            logging.debug("[VT Plugin] File already available in VirusTotal.")

        return False

    def upload_file_to_VT(self):
        """Upload input file to VirusTotal."""

        logging.debug("[VT Plugin] Preparing to upload file to VirusTotal.")

        if not self.api_key:
            logging.info("[VT Plugin] API Key not configured: unable to upload.")
            self.progress = "Upload failed: API Key not configured."
            return

        if not os.path.isfile(self.input_file):
            logging.error("[VT Plugin] Uploading error: invalid input file path.")
            self.progress = "Upload failed: invalid file path."
            return

        logging.info("[VT Plugin] Uploading input file to VirusTotal.")
        self.progress = "Uploading file to VirusTotal..."

        try:
            response = self.client.upload_file(self.input_file)

            if response.ok:
                logging.info("[VT Plugin] Sample uploaded successfully.")
                self.progress = "Upload successful!"
            else:
                logging.error(
                    f"[VT Plugin] Upload failed: {response.status_code} - {response.text}"
                )
                self.progress = f"Upload failed: {response.status_code}"
        except Exception:
            logging.error("[VT Plugin] Unable to connect to VirusTotal.com for upload.")
            self.progress = "Upload failed: connection error."

    def run(self):
        self.progress = f"Starting check for {os.path.basename(self.input_file)}..."

        if self.file_exists_on_disk() and self.check_file_missing_in_VT() and self.auto_upload:
            self.upload_file_to_VT()
