import binaryninja as bn
import logging
from ...virustotal import vtgrep
from ...ui.commands.binary_view_validator import BinaryViewValidator

class VTGrepSimilarFunctionsCommand:
    NAME = "VirusTotal\\Search for similar functions"
    DESCRIPTION = "Search for similar functions in VirusTotal"

    @staticmethod
    def execute(bv: bn.BinaryView, func: bn.Function):
        start = func.start
        end = func.highest_address + 1

        logging.info(
            "[VTGREP] Search similar functions: %s [%s-%s] (%d bytes)",
            func.name,
            hex(start),
            hex(end),
            end - start,
        )

        if func.address_ranges and len(func.address_ranges) > 1:
            logging.debug("[VTGREP] Non-contiguous func (%d ranges); checking union.", len(func.address_ranges))

        searcher = vtgrep.VTGrepSearch(
            bv=bv,
            addr_start=start,
            addr_end=end,
        )
        searcher.search(wildcards=True, strict=False)

    @staticmethod
    def is_command_available(bv: bn.BinaryView, func: bn.Function) -> bool:
        if not BinaryViewValidator.supports_similar_code(bv):
            return False
        return BinaryViewValidator.is_valid_function(bv, func)
