import binaryninja as bn
import logging
from ...virustotal import vtgrep
from ...ui.commands.binary_view_validator import BinaryViewValidator

class VTGrepBytesCommand:
    NAME = "VirusTotal\\Search for bytes"
    DESCRIPTION = "Search the selected bytes in VirusTotal"

    @staticmethod
    def execute(bv: bn.BinaryView, addr: int, length: int):
        addr_end = addr + length

        logging.debug(f"[VT] Initiating Search for Bytes: {hex(addr)} - {hex(addr_end)}")

        searcher = vtgrep.VTGrepSearch(
            bv=bv,
            addr_start=addr,
            addr_end=addr_end
        )

        searcher.search(wildcards=False)

    @staticmethod
    def is_command_available(bv: bn.BinaryView, addr: int, length: int) -> bool:
        return BinaryViewValidator.is_valid_range(bv, addr, addr + length)

