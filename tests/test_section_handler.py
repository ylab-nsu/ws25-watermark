import os

import pytest

from watermark_framework.architecture import Architecture
from watermark_framework.io import TextSection, TextSectionHandler

TEST_DATA_DIR = "tests/data"


@pytest.mark.parametrize(
    "elf_file,arch",
    [
        ("test_x86.elf", Architecture.X86_64),
        ("test_riscv.elf", Architecture.RISCV),
    ],
)
def test_load_valid_elf(elf_file, arch):
    """
    Test loading valid ELF files for supported architectures.
    """
    path = os.path.join(TEST_DATA_DIR, elf_file)
    section = TextSectionHandler.load(path)

    assert isinstance(section, TextSection)
    assert section.arch == arch
    assert len(section.data) > 100
    assert section.size == len(section.data)
    assert section.vma > 0
    assert len(section.insns) > 20


def test_load_unsupported_arch():
    """
    Test loading an ELF file with an unsupported architecture (MIPS).
    """
    path = os.path.join(TEST_DATA_DIR, "test_mips.elf")
    with pytest.raises(ValueError, match="Unsupported architecture"):
        TextSectionHandler.load(path)


@pytest.mark.parametrize(
    "elf_file",
    [
        "test_x86.elf",
        "test_riscv.elf",
    ],
)
def test_write_valid(elf_file):
    """
    Test writing modified ELF files with valid data.
    """
    path = os.path.join(TEST_DATA_DIR, elf_file)
    section = TextSectionHandler.load(path)
    new_data = section.data

    output_path = f"modified_{elf_file}"
    TextSectionHandler.write(section, output_path, new_data)
    assert os.path.exists(output_path)

    with open(path, "rb") as f:
        original = f.read()
    with open(output_path, "rb") as f:
        modified = f.read()
    assert len(modified) == len(original)

    modified_text = modified[section.offset : section.offset + section.size]
    assert modified_text == new_data

    os.remove(output_path)


def test_write_oversized_data():
    """
    Test writing with data larger than the .text section size.
    """
    path = os.path.join(TEST_DATA_DIR, "test_x86.elf")
    section = TextSectionHandler.load(path)
    new_data = section.data + b"extra"
    with pytest.raises(ValueError, match="exceeds"):
        TextSectionHandler.write(section, "modified.elf", new_data)


def test_write_empty_section():
    """
    Test writing to an empty .text section.
    """
    path = os.path.join(TEST_DATA_DIR, "test_x86.elf")
    section = TextSectionHandler.load(path)
    section.size = 0
    with pytest.raises(ValueError, match="empty"):
        TextSectionHandler.write(section, "modified.elf", b"")
