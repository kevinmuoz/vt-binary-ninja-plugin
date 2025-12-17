import logging

import binaryninja as bn
from .binary_view_validator import BinaryViewValidator
from ...virustotal.codeinsight import CodeInsightExtractor
from binaryninjaui import UIContext

class CodeInsightFactoryCommand:
    NAME = "VirusTotal\\Ask Code Insight"
    DESCRIPTION = "Ask VirusTotal Code Insight for the current function"

    MIN_QUERY_SIZE = 40
    MAX_QUERY_SIZE = 4096

    @staticmethod
    def execute(bv: bn.BinaryView, func: bn.Function):
        # validate view type
        view_type = CodeInsightExtractor.get_current_view_type()

        if view_type is None:
            bn.show_message_box(
                "VirusTotal Code Insight",
                "Unsupported view type. Please switch to Disassembly or Pseudo-C view.",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.WarningIcon,
            )
            return

        logging.debug(f"[VT] Code Insight activated for function {func.name} @ 0x{func.start:x}, view_type={view_type}")

        # extract code
        code_content = CodeInsightExtractor.get_current_code(bv, func)

        if not code_content:
            bn.show_message_box(
                "VirusTotal Code Insight",
                "Failed to generate code content from the current view.",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.ErrorIcon,
            )
            return

        logging.debug(f"[VT] Code content extracted ({len(code_content)} bytes)")

        # validate byte size
        code_length = len(code_content)
        
        if code_length < CodeInsightFactoryCommand.MIN_QUERY_SIZE:
            bn.show_message_box(
                "VirusTotal Code Insight",
                f"The code is too short for analysis.\n\n"
                f"Minimum size: {CodeInsightFactoryCommand.MIN_QUERY_SIZE} characters\n"
                f"Current size: {code_length} characters",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.WarningIcon,
            )
            return

        if code_length > CodeInsightFactoryCommand.MAX_QUERY_SIZE:
            bn.show_message_box(
                "VirusTotal Code Insight",
                f"The code is too large for analysis.\n\n"
                f"Maximum size: {CodeInsightFactoryCommand.MAX_QUERY_SIZE} characters\n"
                f"Current size: {code_length} characters",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.WarningIcon,
            )
            return

        # open sidebar and start analysis
        CodeInsightFactoryCommand.open_code_insight_sidebar_section()
        CodeInsightFactoryCommand.start_ci_analysis(func, code_content, view_type)

    @staticmethod
    def is_command_available(bv: bn.BinaryView, func: bn.Function) -> bool:
        if not BinaryViewValidator.is_valid_function(bv, func):
            return False

        view_type = CodeInsightExtractor.get_current_view_type()
        if view_type == 'disassembled' or view_type == 'decompiled':
            return True            

        return False

    @staticmethod
    def open_code_insight_sidebar_section():
        try:
            logging.debug("[VT] Opening VirusTotal sidebar for BV")
            ctx = UIContext.activeContext()
            if not ctx:
                return

            sidebar = ctx.sidebar()
            
            if not sidebar:
                return
            sidebar.activate("VirusTotal")

            vt_widget = sidebar.widget("VirusTotal")

            if vt_widget:
                vt_widget.show_code_insight_tab()
        except Exception as e:
            logging.debug(f"[VT] Opening VirusTotal sidebar for BV failed: {e}")

    @staticmethod
    def start_ci_analysis(func: bn.Function, code_content: str, view_type: str):
        try:
            ctx = UIContext.activeContext()
            if not ctx:
                logging.error("[VT] No active UI context")
                return

            sidebar = ctx.sidebar()
            if not sidebar:
                logging.error("[VT] No sidebar available")
                return

            vt_widget = sidebar.widget("VirusTotal")
            if not vt_widget or not hasattr(vt_widget, 'code_tab'):
                logging.error("[VT] Code Insight tab not available")
                return

            # Start the analysis
            vt_widget.code_tab.start_analysis(func, code_content, view_type)

        except Exception as e:
            logging.error(f"[VT] Error starting Code Insight analysis: {e}")
            bn.show_message_box(
                "VirusTotal Code Insight",
                f"Failed to start analysis: {str(e)}",
                bn.MessageBoxButtonSet.OKButtonSet,
                bn.MessageBoxIcon.ErrorIcon,
            )
