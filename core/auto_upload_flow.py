from ..ui.dialogs.consent_upload import show_consent_upload_dialog
from .vt_settings import settings
from ..virustotal.check_sample import CheckSample
import binaryninja as bn
import logging

class AutoUploadFlow:
    """
    Implements the decision logic for auto-upload permissions, including checking
    stored settings and prompting the user when required.

    Returns:
    "ok"     - uploads allowed (automatically)
    "no"     - uploads permanently disabled
    "cancel" - user aborted this operation
    """

    @staticmethod
    def resolve_auto_upload_consent(bv: bn.BinaryView) -> str:
        """
        Ensures user consent before performing any operation that may upload samples to VT.

        Returns:
            "ok"     - uploads allowed (automatically)
            "no"     - uploads permanently disabled
            "cancel" - user aborted this operation
        """

        should_ask = settings.should_ask_for_consent()
        auto_upload = settings.get_auto_upload_consent()

        logging.debug(f"[VT] Should ask for consent: {should_ask}")

        if not should_ask:
            if auto_upload:
                has_api_key = bool(settings.get_api_key())
                if has_api_key:
                    logging.debug(
                        "[VT] Consent previously given. Initiating automatic upload."
                    )
                    uploader = CheckSample(
                        bv, auto_upload=True, api_key=settings.get_api_key()
                    )
                    uploader.start()
                return "ok"

            return "no"

        logging.debug("[VT] User consent required for uploads...")
        result = show_consent_upload_dialog()
        settings.set_user_asked(True)

        if result == "ok":
            settings.set_auto_upload_consent(True)

            has_api_key = bool(settings.get_api_key())
            if has_api_key:
                logging.debug(
                    "[VT] API key configured, proceeding with manual upload initiation."
                )
                uploader = CheckSample(
                    bv, auto_upload=True, api_key=settings.get_api_key()
                )
                uploader.start()

            return "ok"

        if result == "no":
            settings.set_auto_upload_consent(False)
            return "no"

        return "cancel"
