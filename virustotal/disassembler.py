import logging
from typing import Tuple, List

import binaryninja as bn
from binaryninja.enums import InstructionTextTokenType, BranchType


class Disassembler:
    """Helper class for generating VTGrep-compatible byte patterns."""

    WILDCARD_BRANCH_TYPES = frozenset(
        {
            BranchType.CallDestination,
            BranchType.UnconditionalBranch,
            BranchType.TrueBranch,
            BranchType.FalseBranch,
            BranchType.UnresolvedBranch,
            BranchType.IndirectBranch,
            BranchType.SystemCall,
        }
    )

    @staticmethod
    def next_address(bv: bn.BinaryView, addr: int) -> int:
        """Get the address immediately after the instruction at addr."""
        length = bv.get_instruction_length(addr)
        return addr + (length if length > 0 else 1)

    @staticmethod
    def get_bytes(bv: bn.BinaryView, start: int, end: int) -> bytes:
        """Read raw bytes from the BinaryView."""
        length = end - start
        return bv.read(start, length) if length > 0 else b""

    @staticmethod
    def valid_address_range(start: int, end: int) -> bool:
        """Check if address range is valid."""
        return start is not None and end is not None and end > start

    @staticmethod
    def valid_range_size(start: int, end: int, max_size: int) -> bool:
        """Check if selection does not exceed maximum size."""
        return (end - start) <= max_size

    @staticmethod
    def get_opcodes(bv: bn.BinaryView, addr: int, strict: bool = False) -> str:
        """
        Generate a hexadecimal opcode pattern for the instruction at the given address.

        The returned pattern is suitable for VTGrep "similar code" searches and applies
        wildcards ("??") to bytes that are likely to vary between binaries, such as
        addresses, offsets, and relocation targets.

        Resolution strategy:

        1. Relocations:
           If relocation metadata is available, apply precise per-byte wildcarding.
           This provides the most accurate results, especially in non-stripped binaries.

        2. Control-flow heuristics:
           When relocations are not available, analyze the instruction semantics:
           - Branches and calls: wildcard the target address or displacement.
           - Short local branches (e.g., small relative jumps): keep bytes literal.

        3. Address references:
           Instructions referencing addresses within known binary sections are
           wildcarded to avoid overfitting absolute addresses.

        4. Token-based address detection:
           If Binary Ninja instruction tokens indicate address usage, wildcard the
           corresponding bytes.

        5. Fallback:
           If none of the above apply, return the instruction bytes verbatim.
        """

        length = bv.get_instruction_length(addr)
        if length <= 0:
            return "00"

        raw = bv.read(addr, length)
        if not raw:
            return "00"

        # relocations
        relocs = bv.relocation_ranges_in_range(addr, length)
        if relocs:
            return Disassembler._pattern_from_relocs(raw, addr, relocs)

        # control flow analysis
        is_branch, is_short = Disassembler._check_control_flow(bv, raw, addr)
        if is_short:
            return Disassembler._pattern_literal(raw)
        if is_branch:
            return Disassembler._pattern_wildcard(raw, bv.address_size)

        # references to binary sections
        if Disassembler._has_section_references(bv, addr):
            return Disassembler._pattern_wildcard(raw, bv.address_size)

        # tokens pointing to binary sections
        if Disassembler._has_address_tokens(bv, addr):
            return Disassembler._pattern_wildcard(raw, bv.address_size)

        # literal bytes
        return Disassembler._pattern_literal(raw)

    @staticmethod
    def _is_in_section(bv: bn.BinaryView, value: int) -> bool:
        """Check if value points to an address within binary sections."""
        return bool(bv.get_sections_at(value))

    @staticmethod
    def _check_control_flow(
        bv: bn.BinaryView, raw: bytes, addr: int
    ) -> Tuple[bool, bool]:
        """
        Returns (is_wildcard_branch, is_short_branch).
        Short branches (<=2 bytes) are local jumps - don't wildcard.
        """
        try:
            info = bv.arch.get_instruction_info(raw, addr)
            if not info or not info.branches:
                return False, False

            for branch in info.branches:
                if branch.type in Disassembler.WILDCARD_BRANCH_TYPES:
                    is_short = len(raw) <= 2
                    return (not is_short), is_short

            return False, False
        except Exception:
            return False, False

    @staticmethod
    def _has_section_references(bv: bn.BinaryView, addr: int) -> bool:
        """Check if instruction references addresses in binary sections."""
        try:
            # Code refs (calls, jumps)
            for ref in bv.get_code_refs_from(addr):
                if Disassembler._is_in_section(bv, ref):
                    return True

            # Data refs
            for ref in bv.get_data_refs_from(addr):
                if Disassembler._is_in_section(bv, ref):
                    return True

            return False
        except Exception:
            return False

    @staticmethod
    def _has_address_tokens(bv: bn.BinaryView, addr: int) -> bool:
        """Check if instruction tokens contain addresses pointing to binary sections."""
        try:
            tokens, _ = next(bv.disassembly_tokens(addr))
            for t in tokens:
                if t.type in (
                    InstructionTextTokenType.PossibleAddressToken,
                    InstructionTextTokenType.IntegerToken,
                ):
                    try:
                        if Disassembler._is_in_section(bv, t.value):
                            return True
                    except Exception:
                        pass
            return False
        except Exception:
            return False

    @staticmethod
    def _pattern_from_relocs(
        raw: bytes, addr: int, relocs: List[Tuple[int, int]]
    ) -> str:
        """Build pattern using relocation information."""
        parts = []
        for i, byte in enumerate(raw):
            byte_addr = addr + i
            is_reloc = any(start <= byte_addr < end for start, end in relocs)
            parts.append("??" if is_reloc else f"{byte:02X}")
        pattern = " ".join(parts)
        logging.debug("[VTGREP] Pattern (relocs): %s", pattern)
        return pattern

    @staticmethod
    def _pattern_wildcard(raw: bytes, addr_size: int) -> str:
        """Build pattern: keep opcode, wildcard operand bytes."""
        length = len(raw)
        wildcard_count = min(addr_size, length - 1)
        keep_count = max(1, length - wildcard_count)

        parts = [f"{b:02X}" for b in raw[:keep_count]]
        parts.extend(["??"] * wildcard_count)
        pattern = " ".join(parts)
        logging.debug("[VTGREP] Pattern (wildcard): %s", pattern)
        return pattern

    @staticmethod
    def _pattern_literal(raw: bytes) -> str:
        """Build pattern with all literal bytes."""
        pattern = " ".join(f"{b:02X}" for b in raw)
        logging.debug("[VTGREP] Pattern (literal): %s", pattern)
        return pattern
