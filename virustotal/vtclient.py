import requests
import logging
import os
from ..core import config

VT_API_BASE = "https://www.virustotal.com/api/v3"


class VTClient:
    def __init__(
        self,
        api_key: str,
        user_agent: str = f"BN VT Plugin {config.VT_BN_PLUGIN_VERSION}",
    ):
        self.api_key = api_key
        self.user_agent = user_agent

    @property
    def _headers(self) -> dict:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "x-apikey": self.api_key,
        }

    def get_file(self, file_hash: str):
        url = f"{VT_API_BASE}/files/{file_hash}"
        logging.debug("[VT] Checking hash: %s", file_hash)
        return requests.get(url, headers=self._headers)

    def upload_file(self, path: str):
        url = f"{VT_API_BASE}/files"
        with open(path, "rb") as f:
            files = {"file": (os.path.basename(path), f)}
            return requests.post(url, headers=self._headers, files=files)
