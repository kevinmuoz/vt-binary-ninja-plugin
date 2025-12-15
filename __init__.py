import binaryninja as bn
from binaryninjaui import Sidebar
import logging
import sys
from pathlib import Path
from .core.auto_upload_flow import AutoUploadFlow
from .core.vt_settings import settings  # noqa: F401
from .core import config
from .ui.context_menu import register_context_menu
from .ui.vt_sidebar import VTSidebarWidgetType

def setup_logging(debug=False, save_to_file=False):
    handlers = []

    handlers.append(logging.StreamHandler(sys.stdout))

    # Optional file logging for debugging
    if save_to_file:
        plugin_dir = Path(__file__).parent
        log_file = plugin_dir / "vt_bn_plugin.log"
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(message)s",
        handlers=handlers,
    )

    logging.info("[VT] %s logging enabled", "Debug" if debug else "Info")


def on_analysis_complete(bv: bn.BinaryView):
    """
    Handler for the BinaryView analysis complete event.
    """
    logging.debug(f"[VT-EVENT] Analysis Complete: {bv.file.filename}")
    bn.mainthread.execute_on_main_thread(
        lambda: AutoUploadFlow.resolve_auto_upload_consent(bv)
    )


def register_view_events():
    """
    Register global BinaryView events.
    """

    bn.BinaryViewType.add_binaryview_initial_analysis_completion_event(
        on_analysis_complete
    )
    logging.debug("[VT-EVENT] BinaryViewType global events registered")


def init_plugin():
    try:
        bn.log_info(
            f"[VT] Initializing VirusTotal Plugin v{config.VT_BN_PLUGIN_VERSION}"
        )
        setup_logging(debug=config.DEBUG, save_to_file=config.SAVE_LOG_TO_FILE)
        register_view_events()
        Sidebar.addSidebarWidgetType(VTSidebarWidgetType())
        register_context_menu()
        
    except Exception as e:
        bn.log_error(f"[VT] Error during plugin initialization: {e}")
        return

init_plugin()