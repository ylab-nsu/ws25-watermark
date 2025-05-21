from enum import Enum
from typing import Optional

from capstone import (
    CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCV32, CS_MODE_RISCVC,
    CS_ARCH_X86, CS_MODE_32,
    CS_ARCH_ARM64, CS_MODE_ARM
)

from elftools.elf.enums import ENUM_E_MACHINE, ENUM_EI_CLASS

class Architecture(Enum):
    """
    Enum representing supported CPU architectures with associated metadata.

    Each member contains:
    - arch_name: Human-readable architecture name.
    - capstone_arch: Capstone architecture constant.
    - capstone_mode: Capstone mode constant (or combined modes).
    - e_machine: ELF machine type identifier.
    - elf_class: ELF class (32-bit or 64-bit, or None for flexible architectures).
    """
    I386 = ("i386", CS_ARCH_X86, CS_MODE_32, ENUM_E_MACHINE['EM_386'], ENUM_EI_CLASS['ELFCLASS32']) #type: ignore
    RISCV = ("riscv", CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCV32 | CS_MODE_RISCVC, ENUM_E_MACHINE['EM_RISCV'], None) #type: ignore
    ARM64 = ("arm64", CS_ARCH_ARM64, CS_MODE_ARM, ENUM_E_MACHINE['EM_AARCH64'], ENUM_EI_CLASS['ELFCLASS64']) #type: ignore

    def __init__(self, name: str, capstone_arch: int, capstone_mode: int, 
                 e_machine: int, elf_class: Optional[int]):
        """Initialize an Architecture member with its metadata."""
        self.arch_name = name
        self.capstone_arch = capstone_arch
        self.capstone_mode = capstone_mode
        self.e_machine = e_machine
        self.elf_class = elf_class

    @property
    def capstone_config(self) -> tuple[int, int]:
        """Return Capstone (arch, mode) tuple for disassembly configuration."""
        return (self.capstone_arch, self.capstone_mode)

    @classmethod
    def from_elf(cls, e_machine: int, elf_class: int) -> 'Architecture':
        for arch in cls:
            if arch.e_machine == e_machine:
                if arch.elf_class is None or arch.elf_class == elf_class:
                    return arch
        raise ValueError(f"Unsupported architecture: e_machine={e_machine}, elf_class={elf_class}")