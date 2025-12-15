import binaryninja as bn
import logging
from ...virustotal import vtgrep
from ...ui.commands.binary_view_validator import BinaryViewValidator

class VTGrepSimilarCodeCommand:
    NAME = "VirusTotal\\Search for similar code"
    DESCRIPTION = "Search functionally similar code in VirusTotal"

    @staticmethod
    def execute(bv: bn.BinaryView, addr: int, length: int):
        addr_end = addr + length

        logging.debug(f"[VT] Initiating Search for Similar Code: {hex(addr)} - {hex(addr_end)}")

        searcher = vtgrep.VTGrepSearch(
            bv=bv,
            addr_start=addr,
            addr_end=addr_end
        )

        searcher.search(wildcards=True, strict=False)

    @staticmethod
    def is_command_available(bv: bn.BinaryView, addr: int, length: int) -> bool:
        if bv is None or length <= 0:
            return False
        if not BinaryViewValidator.supports_similar_code(bv):
            return False
        return BinaryViewValidator.is_valid_range(bv, addr, addr + length)

