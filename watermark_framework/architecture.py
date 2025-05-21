from enum import Enum
from typing import Optional

from capstone import (
    CS_ARCH_ARM64,
    CS_ARCH_RISCV,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_ARM,
    CS_MODE_RISCV32,
    CS_MODE_RISCV64,
    CS_MODE_RISCVC,
)


class Architecture(Enum):
    """
    Enum representing supported CPU architectures with associated metadata.

    Each member contains:
    - arch_name: Human-readable architecture name.
    - capstone_arch: Capstone architecture constant.
    - capstone_mode: Capstone mode constant (or combined modes).
    - e_machine: ELF machine type string identifier(e.g., 'EM_386').
    - elf_class: ELF class (32 or 64, or None for flexible architectures).
    """
    I386 = ("i386", CS_ARCH_X86, CS_MODE_32, 'EM_386', 32)
    RISCV = ("riscv", CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCV64 | CS_MODE_RISCVC, 'EM_RISCV', None)
    ARM64 = ("arm64", CS_ARCH_ARM64, CS_MODE_ARM, 'EM_AARCH64', 64)

    def __init__(self, arch_name: str, capstone_arch: int, capstone_mode: int,
                 e_machine: str, elf_class: Optional[int]):
        self.arch_name = arch_name
        self.capstone_arch = capstone_arch
        self.capstone_mode = capstone_mode
        self.e_machine = e_machine
        self.elf_class = elf_class

    @classmethod
    def from_elf(cls, e_machine: str, elf_class: int) -> 'Architecture':
        """
        Match ELF header values to an architecture.

        Args:
            e_machine: ELF machine string (e.g., 'EM_386').
            elf_class: ELF class (32 or 64).

        Returns:
            Matching Architecture enum member.

        Raises:
            ValueError: If no match is found.
        """
        for arch in cls:
            if arch.e_machine == e_machine:
                if arch.elf_class is None or arch.elf_class == elf_class:
                    return arch
        raise ValueError(f"Unsupported architecture: {e_machine}, {elf_class}")
