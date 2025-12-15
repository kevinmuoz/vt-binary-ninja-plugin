import binaryninja as bn
from typing import Optional

SUPPORTED_CODE_ARCHES = {
    "x86", "x86_64", "x86_16",
    "armv7", "thumb2", "armv7eb", "thumb2eb",
    "aarch64",
    "mips32", "mipsel32"
}

SUPPORTED_STRICT_ARCHES = {
    "x86", "x86_64", "x86_16"
}

class BinaryViewValidator:
    """
    Helper class to determine whether registered plugin commands
    can be executed in the current BinaryView UI context.
    """

    @staticmethod
    def is_valid_address(bv: bn.BinaryView, addr: int) -> bool:
        """
        Check if an address is valid and contains code or data.
        
        Args:
            bv: Binary view to validate against
            addr: Address to check
            
        Returns:
            True if address is valid and accessible
        """
        if bv is None or addr is None:
            return False

        if not bv.is_valid_offset(addr):
            return False

        return False
    
    @staticmethod
    def is_valid_function(bv: bn.BinaryView, func: Optional[bn.Function]) -> bool:
        """
        Check if a function is valid and has content.
        
        Args:
            bv: Binary view containing the function
            func: Function to validate
            
        Returns:
            True if function exists and has non-zero size
        """
        if bv is None or func is None:
            return False
            
        return func.total_bytes > 0
    
    @staticmethod
    def is_valid_range(bv: bn.BinaryView, start: int, end: int) -> bool:
        """
        Check if a memory range is valid.
        
        Args:
            bv: Binary view to check
            start: Start address
            end: End address
            
        Returns:
            True if range is valid and within bounds
        """
        if bv is None or start is None or end is None:
            return False
            
        if start >= end:
            return False
            
        return (bv.is_valid_offset(start) and 
                bv.is_valid_offset(end - 1))
    
    @staticmethod
    def arch_name(bv: bn.BinaryView) -> str:
        """Safe arch name getter"""
        try:
            return getattr(getattr(bv, "arch", None), "name", "") or ""
        except Exception:
            return ""

    @staticmethod
    def supports_similar_code(bv: bn.BinaryView) -> bool:
        return BinaryViewValidator.arch_name(bv) in SUPPORTED_CODE_ARCHES

    @staticmethod
    def supports_strict(bv: bn.BinaryView) -> bool:
        return BinaryViewValidator.arch_name(bv) in SUPPORTED_STRICT_ARCHES