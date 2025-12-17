from __future__ import annotations

import logging
from typing import Tuple, Optional

import binaryninja as bn
from binaryninjaui import (
    Menu,
    UIAction,
    UIActionHandler,
    UIContext,
    UIContextNotification,
    UIActionContext,
    View,
)

from ..ui.commands.grep_bytes_command import VTGrepBytesCommand
from ..ui.commands.grep_similar_code_command import VTGrepSimilarCodeCommand
from ..ui.commands.grep_similar_functions_command import VTGrepSimilarFunctionsCommand
from ..ui.commands.code_insights_command import CodeInsightFactoryCommand

class VTAction:
    """Represents a VirusTotal context menu action."""

    MENU_GROUP = "VirusTotal"

    def __init__(self, name: str, description: str, priority: int) -> None:
        self.name = name
        self.description = description
        self.priority = priority

    @property
    def full_name(self) -> str:
        """Full action name with group prefix for menu hierarchy."""
        return f"{self.MENU_GROUP}\\{self.name}"


class VTActions:
    """Registry of all VirusTotal context menu actions."""

    ASK_TO_CODE_INSIGHT = VTAction(
        name="Ask Code Insight",
        description="Ask VirusTotal Code Insight for the current function",
        priority=0,
    )

    SEARCH_BYTES = VTAction(
        name="Search for bytes",
        description="Search the selected bytes in VirusTotal",
        priority=1,
    )

    SEARCH_SIMILAR_CODE = VTAction(
        name="Search for similar code",
        description="Search functionally similar code in VirusTotal",
        priority=2,
    )

    SEARCH_SIMILAR_FUNCTIONS = VTAction(
        name="Search for similar functions",
        description="Search for similar functions in VirusTotal",
        priority=3,
    )

    ALL: Tuple[VTAction, ...] = (
        ASK_TO_CODE_INSIGHT,
        SEARCH_BYTES,
        SEARCH_SIMILAR_CODE,
        SEARCH_SIMILAR_FUNCTIONS,
    )


class ContextExtractor:
    """Extracts typed context data from UIActionContext."""

    @staticmethod
    def get_range(ctx: UIActionContext) -> Optional[Tuple[bn.BinaryView, int, int]]:
        """
        Extract range selection context.

        Returns:
            Tuple of (binary_view, address, length) or None if unavailable.
        """
        bv: Optional[bn.BinaryView] = getattr(ctx, "binaryView", None)
        addr: Optional[int] = getattr(ctx, "address", None)
        length: Optional[int] = getattr(ctx, "length", None)

        if bv is None or addr is None or length is None:
            return None

        return bv, addr, length

    @staticmethod
    def get_function(ctx: UIActionContext) -> Optional[Tuple[bn.BinaryView, bn.Function]]:
        """
        Extract function context.

        Returns:
            Tuple of (binary_view, function) or None if unavailable.
        """
        bv: Optional[bn.BinaryView] = getattr(ctx, "binaryView", None)
        func: Optional[bn.Function] = getattr(ctx, "function", None)

        if bv is None or func is None:
            return None

        return bv, func


class VTActionHandlers:
    """Callback handlers that bridge UIAction to Command classes."""

    # Ask code insight
    @staticmethod
    def execute_ask_code_insight(ctx: UIActionContext) -> None:
        data = ContextExtractor.get_function(ctx)
        if data:
            bv, func = data
            CodeInsightFactoryCommand.execute(bv, func)

    @staticmethod
    def is_ask_code_insight_available(ctx: UIActionContext) -> bool:
        data = ContextExtractor.get_function(ctx)
        if not data:
            return False
        bv, func = data
        return CodeInsightFactoryCommand.is_command_available(bv, func)

    # Search for bytes
    @staticmethod
    def execute_search_bytes(ctx: UIActionContext) -> None:
        data = ContextExtractor.get_range(ctx)
        if data:
            bv, addr, length = data
            VTGrepBytesCommand.execute(bv, addr, length)

    @staticmethod
    def is_search_bytes_available(ctx: UIActionContext) -> bool:
        data = ContextExtractor.get_range(ctx)
        if not data:
            return False
        bv, addr, length = data
        return VTGrepBytesCommand.is_command_available(bv, addr, length)

    # Search for similar code
    @staticmethod
    def execute_search_similar_code(ctx: UIActionContext) -> None:
        data = ContextExtractor.get_range(ctx)
        if data:
            bv, addr, length = data
            VTGrepSimilarCodeCommand.execute(bv, addr, length)

    @staticmethod
    def is_search_similar_code_available(ctx: UIActionContext) -> bool:
        data = ContextExtractor.get_range(ctx)
        if not data:
            return False
        bv, addr, length = data
        return VTGrepSimilarCodeCommand.is_command_available(bv, addr, length)

    # Search for similar functions
    @staticmethod
    def execute_search_similar_functions(ctx: UIActionContext) -> None:
        data = ContextExtractor.get_function(ctx)
        if data:
            bv, func = data
            VTGrepSimilarFunctionsCommand.execute(bv, func)

    @staticmethod
    def is_search_similar_functions_available(ctx: UIActionContext) -> bool:
        data = ContextExtractor.get_function(ctx)
        if not data:
            return False
        bv, func = data
        return VTGrepSimilarFunctionsCommand.is_command_available(bv, func)


class VTContextMenuNotification(UIContextNotification):
    """
    Injects VirusTotal actions into Binary Ninja context menu.
    """

    def OnContextMenuCreated(
        self,
        context: UIContext,
        view: View,
        menu: Menu,
    ) -> None:
        if menu is None:
            return

        try:
            self._remove_stale_actions(menu)
            self._inject_actions(menu)
        except Exception as e:
            logging.debug("[VT] Context menu injection error: %s", e)

    def _remove_stale_actions(self, menu: Menu) -> None:
        """Remove any previously injected actions to prevent duplicates."""
        try:
            existing_actions = menu.getActions()
            for action_key in list(existing_actions.keys()):
                for vt_action in VTActions.ALL:
                    if action_key == vt_action.full_name:
                        menu.removeAction(action_key)
        except Exception:
            pass

    def _inject_actions(self, menu: Menu) -> None:
        """Inject all VirusTotal actions into the menu."""
        for action in VTActions.ALL:
            menu.addAction(action.full_name, VTAction.MENU_GROUP, action.priority)


# Module-level state to prevent GC
_notification_instance: Optional[VTContextMenuNotification] = None


def _register_ui_actions() -> None:
    """Register all UIActions and bind their handlers."""
    handler = UIActionHandler.globalActions()

    # Ask code insight
    action_code_insight = VTActions.ASK_TO_CODE_INSIGHT
    if not UIAction.isActionRegistered(action_code_insight.full_name):
        UIAction.registerAction(action_code_insight.full_name)
    handler.bindAction(
        action_code_insight.full_name,
        UIAction(
            VTActionHandlers.execute_ask_code_insight,
            VTActionHandlers.is_ask_code_insight_available,
        ),
    )

    # Search for bytes
    action_bytes = VTActions.SEARCH_BYTES
    if not UIAction.isActionRegistered(action_bytes.full_name):
        UIAction.registerAction(action_bytes.full_name)
    handler.bindAction(
        action_bytes.full_name,
        UIAction(
            VTActionHandlers.execute_search_bytes,
            VTActionHandlers.is_search_bytes_available,
        ),
    )

    # Search for similar code
    action_code = VTActions.SEARCH_SIMILAR_CODE
    if not UIAction.isActionRegistered(action_code.full_name):
        UIAction.registerAction(action_code.full_name)
    handler.bindAction(
        action_code.full_name,
        UIAction(
            VTActionHandlers.execute_search_similar_code,
            VTActionHandlers.is_search_similar_code_available,
        ),
    )

    # Search for similar functions
    action_funcs = VTActions.SEARCH_SIMILAR_FUNCTIONS
    if not UIAction.isActionRegistered(action_funcs.full_name):
        UIAction.registerAction(action_funcs.full_name)
    handler.bindAction(
        action_funcs.full_name,
        UIAction(
            VTActionHandlers.execute_search_similar_functions,
            VTActionHandlers.is_search_similar_functions_available,
        ),
    )

    logging.info("[VT] UIActions registered and bound")


def register_context_menu() -> None:
    """
    Initialize VirusTotal context menu integration.

    Call this once during plugin startup to register all context menu actions.
    """
    global _notification_instance

    _register_ui_actions()

    if _notification_instance is None:
        _notification_instance = VTContextMenuNotification()
        bn.mainthread.execute_on_main_thread(
            lambda: UIContext.registerNotification(_notification_instance)
        )
        logging.info("[VT] Context menu integration registered")