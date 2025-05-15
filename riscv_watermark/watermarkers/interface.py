from abc import ABC, abstractmethod

from capstone import CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCV64, CS_MODE_RISCVC, Cs  # type: ignore
from elftools.elf.elffile import ELFFile


class Watermarker(ABC):
    """
    Encodes specific message using selected method
    """

    @abstractmethod
    def encode(self, filename: str, message) -> bytes:
        """Encode message into file. Must be implemented by subclass."""
        pass

    @abstractmethod
    def decode(self, filename: str) -> str:
        """Decode message from file. Must be implemented by subclass."""
        pass

    @abstractmethod
    def get_nbits(self, filename: str) -> int:
        """Return number of bits available. Must be implemented by subclass."""
        pass

    def disassembly(self, filename: str):
        with open(filename, "rb") as f:
            elf = ELFFile(f)
            code = elf.get_section_by_name(".text")
            addr = code["sh_addr"]
            code = code.data()
            md = Cs(
                CS_ARCH_RISCV,
                CS_MODE_RISCV64 | CS_MODE_RISCV32 | CS_MODE_RISCVC,
            )
            return md.disasm(code, addr)
