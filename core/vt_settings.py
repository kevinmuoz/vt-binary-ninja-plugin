import json
import logging
from binaryninja.settings import Settings as BNSettings, SettingsScope

class VTSettings:
    """
    Wrapper around Binary Ninja Settings for VirusTotal integration
    """

    def __init__(self) -> None:
        self._settings = BNSettings(instance_id="default")
        self._register_group_and_settings()

    def _register_group_and_settings(self) -> None:
        """Register the settings group and all keys used by the plugin."""

        self._settings.register_group("virustotal", "VirusTotal")

        api_key_props = {
            "title": "VirusTotal API Key",
            "description": (
                "A valid VirusTotal API key is required for using Code Insights. "
                "VTGrep searches do not require an API key and instead rely on an "
                "active VirusTotal Enterprise session in your web browser."
            ),
            "type": "string",
            "default": "",
            "hidden": True,
            "ignore": ["SettingsProjectScope", "SettingsResourceScope"],
        }

        existsApiKey = self.setting_exists("virustotal.apiKey")
        if not existsApiKey:
            self._settings.register_setting(
                "virustotal.apiKey", json.dumps(api_key_props)
            )

        auto_upload_props = {
            "title": "Auto-Upload Samples",
            "description": (
                "Automatically upload samples to VirusTotal after you have "
                "given explicit consent."
            ),
            "type": "boolean",
            "default": False,
            "ignore": ["SettingsProjectScope", "SettingsResourceScope"],
            "message": (
                "When enabled, this plugin may automatically upload samples to VirusTotal."
            ),
        }

        existsAutoUpload = self.setting_exists("virustotal.autoUpload")
        if not existsAutoUpload:
            self._settings.register_setting(
                "virustotal.autoUpload", json.dumps(auto_upload_props)
            )

        consent_asked_props = {
            "title": "Consent Dialog Displayed",
            "description": "Consent dialog has been shown.",
            "type": "boolean",
            "default": False,
            "ignore": ["SettingsProjectScope", "SettingsResourceScope"],
        }

        existsConsentAsked = self.setting_exists("virustotal.consentAsked")
        if not existsConsentAsked:
            self._settings.register_setting(
                "virustotal.consentAsked", json.dumps(consent_asked_props)
            )

    def setting_exists(self, key: str) -> bool:
        return self._settings.contains(key)

    def get_api_key(self) -> str:
        return self._settings.get_string("virustotal.apiKey")

    def set_api_key(self, api_key: str) -> None:
        self._settings.set_string(
            "virustotal.apiKey",
            api_key,
            scope=SettingsScope.SettingsUserScope,
        )

    def has_user_been_asked(self) -> bool:
        return self._settings.get_bool("virustotal.consentAsked")

    def set_user_asked(self, asked: bool) -> None:
        self._settings.set_bool(
            "virustotal.consentAsked", asked, scope=SettingsScope.SettingsUserScope
        )

    def should_ask_for_consent(self) -> bool:
        if self.has_user_been_asked():
            return False

        if self.get_auto_upload_consent():
            return False

        return True

    def get_auto_upload_consent(self) -> bool:
        return self._settings.get_bool("virustotal.autoUpload")

    def set_auto_upload_consent(self, consent: bool) -> None:
        logging.debug(f"[VT-SETTINGS] Setting auto upload consent to: {consent}")
        self._settings.set_bool(
            "virustotal.autoUpload",
            consent,
            scope=SettingsScope.SettingsUserScope,
        )


settings = VTSettings()
