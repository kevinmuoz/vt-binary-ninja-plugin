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

    def code_insight_analyze(self, payload: dict):
        """
        Send a Code Insight analysis request to VirusTotal.

        Args:
            payload: The request payload containing 'code', 'code_type', and optional 'history'

        Returns:
            Tuple[Optional[str], Optional[str]]: (response_text, error_message)
            - On success: (response_text, None)
            - On error: (None, error_message)
        """
        url = f"{VT_API_BASE}/codeinsights/analyse-binary"
        
        headers = {
            **self._headers,
            "Content-Type": "application/json",
        }

        logging.debug("[VT] Sending Code Insight request")
        logging.debug("[VT] Payload keys: %s", list(payload.keys()))
        logging.debug("[VT] Payload code_type: %s", payload.get("code_type"))
        logging.debug("[VT] Payload history included: %s", "history" in payload)
        logging.debug("[VT] Payload code length: %d", len(payload.get("code", "")))
        logging.debug("[VT Client] raw payload: %s", payload)

        try:
            response = requests.post(
                url,
                json={"data": payload},
                headers=headers,
            )
            
            logging.debug("[VT] Code Insight response status: %d", response.status_code)
            
            # Handle HTTP error codes
            if response.status_code == 401:
                logging.error("[VT] Authentication failed - invalid API key")
                return None, "Authentication failed - Invalid API key"
                
            elif response.status_code == 403:
                logging.error("[VT] Forbidden - insufficient permissions")
                return None, "Access forbidden - Insufficient permissions"
                
            elif response.status_code == 429:
                logging.warning("[VT] Rate limit exceeded (429)")
                return None, "Rate limit exceeded - Please try again later"
                
            elif response.status_code >= 500:
                logging.error("[VT] Server error (%d)", response.status_code)
                return None, f"VirusTotal server error ({response.status_code})"
                
            elif response.status_code != 200:
                logging.error("[VT] Unexpected status code: %d", response.status_code)
                return None, f"API Error (HTTP {response.status_code})"
            
            # Success
            return response.text, None
            
        except requests.exceptions.ConnectionError as e:
            logging.error("[VT] Connection error: %s", str(e))
            return None, "Connection error - Unable to reach VirusTotal"
            
        except requests.exceptions.RequestException as e:
            logging.error("[VT] Request failed: %s", str(e))
            return None, f"Network error: {str(e)}"
