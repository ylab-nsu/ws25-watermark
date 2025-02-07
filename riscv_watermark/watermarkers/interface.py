from abc import ABC, abstractmethod

from capstone import (
    CS_ARCH_RISCV,
    CS_MODE_RISCV32,
    CS_MODE_RISCV64,
    CS_MODE_RISCVC,
    Cs,
)
from elftools.elf.elffile import ELFFile


class Watermarker(ABC):
    """
    Encodes specific message using selected method
    """

    @abstractmethod
    def encode(self, filename: str, message) -> bytes:
        pass

    """
    Gets message using selected method
    """

    @abstractmethod
    def decode(self, filename: str) -> str:
        pass

    """
    Returns amount of bits available to encode using selected method
    """

    @abstractmethod
    def get_nbits(self, filename: str) -> int:
        pass

    def disassembly(self, filename: str):
        with open(filename, 'rb') as f:
            elf = ELFFile(f)
            code = elf.get_section_by_name('.text').data()
            addr = code['sh_addr']
            md = Cs(
                CS_ARCH_RISCV,
                CS_MODE_RISCV64 | CS_MODE_RISCV32 | CS_MODE_RISCVC,
            )
            return md.disasm(code, addr)
