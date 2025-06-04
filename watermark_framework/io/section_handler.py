from dataclasses import dataclass

from capstone import Cs, CsInsn
from elftools.elf.elffile import ELFFile

from watermark_framework.architecture import Architecture


@dataclass
class TextSection:
    """
    Stores metadata and disassembled instructions for an ELF .text section.

    Attributes:
        data (bytes): Raw .text section bytes.
        insns (List[CsInsn]): Disassembled instructions.
        vma (int): Virtual memory address (sh_addr).
        offset (int): File offset (sh_offset).
        size (int): Section size (sh_size).
        arch (Architecture): Architecture (e.g., X86_64, RISCV).
        src_path (str): Path to source ELF file.
        detailed (bool): Whether instructions include detailed analysis info.
    """

    data: bytes
    insns: list["CsInsn"]
    vma: int
    offset: int
    size: int
    arch: Architecture
    src_path: str
    detailed: bool = False


class TextSectionHandler:
    @staticmethod
    def load(path: str, detailed: bool = False) -> TextSection:
        """
        Loads and parses the .text section of an ELF file.

        Reads the ELF file at the specified path, extracts the .text section,
        and disassembles its instructions using Capstone.

        Args:
            path: Path to the ELF file to load.
            detailed: Whether to enable Capstone's detailed mode.

        Returns:
            TextSection: An object containing the .text section's data, disassembled
                instructions, and metadata.

        Raises:
            FileNotFoundError: If the ELF file cannot be opened.
            ValueError: If no .text section is found or the architecture is unsupported.
            RuntimeError: If Capstone disassembly fails.
        """
        with open(path, "rb") as f:
            elf = ELFFile(f)
            arch = Architecture.from_elf(e_machine=elf.header["e_machine"], elf_class=elf.elfclass)

            text_section = elf.get_section_by_name(".text")
            if not text_section:
                raise ValueError("No .text section found in ELF file")
            code = text_section.data()
            addr = text_section.header["sh_addr"]
            offset = text_section.header["sh_offset"]
            size = text_section.header["sh_size"]

            capstone = Cs(arch.capstone_arch, arch.capstone_mode)
            if detailed:
                capstone.detail = True

            insns = list(capstone.disasm(code, addr))

            return TextSection(
                data=code, 
                insns=insns, 
                vma=addr, 
                offset=offset, 
                size=size, 
                arch=arch, 
                src_path=path,
                detailed=detailed
            )

    @staticmethod
    def write(section: TextSection, dst: str, new_data: bytes) -> None:
        """
        Writes a modified ELF file with an updated .text section.

        Creates a new ELF file at the destination path by copying the original file
        and replacing the .text section with the provided data. Ensures the new data
        does not exceed the original .text section size.

        Args:
            section: TextSection object containing the original .text section metadata.
            dst: Path to write the modified ELF file.
            new_data: New bytes to write to the .text section.

        Raises:
            ValueError: If the .text section is empty or new_data size exceeds the
                original .text section size.
            FileNotFoundError: If the source ELF file cannot be read.
            IOError: If writing to the destination file fails.
        """
        if section.size == 0:
            raise ValueError("Cannot patch empty .text section")
        if len(new_data) > section.size:
            raise ValueError(f"New data size ({len(new_data)}) exceeds .text section size ({section.size})")

        with open(section.src_path, "rb") as source_file:
            original_data = source_file.read()

        with open(dst, "wb") as target_file:
            target_file.write(original_data)
            target_file.seek(section.offset)
            target_file.write(new_data)
