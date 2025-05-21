from dataclasses import dataclass
from typing import List

from capstone import Cs, CsInsn
from elftools.elf.elffile import ELFFile

from watermark_framework.architecture import Architecture


@dataclass
class TextSection:
    data: bytes
    insns: List['CsInsn']
    vma: int
    offset: int
    size: int
    arch: Architecture
    src_path: str

class TextSectionHandler:
    @staticmethod
    def load(path: str) -> TextSection:
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            arch = Architecture.from_elf(
                e_machine=elf.header['e_machine'],
                elf_class=elf.elfclass
            )

            text_section = elf.get_section_by_name('.text')
            if not text_section:
                raise ValueError("No .text section found in ELF file")
            code = text_section.data()
            addr = text_section.header['sh_addr']
            offset = text_section.header['sh_offset']
            size = text_section.header['sh_size']

            capstone = Cs(arch.capstone_arch, arch.capstone_mode)
            insns = list(capstone.disasm(code, addr))

            return TextSection(
                data=code,
                insns=insns,
                vma=addr,
                offset=offset,
                size=size,
                arch=arch,
                src_path=path
            )

    @staticmethod
    def write(section: TextSection, dst: str, new_data: bytes) -> None:
        if len(new_data) > section.size:
            raise ValueError("New data exceeds original .text section size")

        with open(section.src_path, 'rb') as f:
            data = bytearray(f.read())
        data[section.offset:section.offset + len(new_data)] = new_data
        with open(dst, 'wb') as f:
            f.write(data)
