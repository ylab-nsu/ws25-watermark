import os
from pathlib import Path
import subprocess

import pytest

from watermark_framework.core.service import WatermarkService
from watermark_framework.watermarkers import get_strategy

PROJECT_ROOT = Path(__file__).parent.parent
EXAMPLE_BINS_DIR = PROJECT_ROOT / "example_bins"

TEST_PROGRAMS = {
    "echo.elf": {"args": ["Hello, World!"], "expected_output": "Hello, World!"},
    "cat.elf": {"args": ["test.txt"], "expected_output": "test content"},
}

SECRET_MESSAGE = "This file has been signed with watermark-framework"


def run_qemu_test(program_path, args):
    """
    Runs a program in QEMU and returns its output.

    :param program_path: Path to the executable file
    :type program_path: Path
    :param args: List of command line arguments
    :type args: List[str]
    :return: Program output
    :rtype: str
    :raises: pytest.fail if program exits with error
    """
    program_path = str(program_path)
    current_mode = os.stat(program_path).st_mode
    if not current_mode & 0o111:
        os.chmod(program_path, current_mode | 0o111)

    cmd = [
        "qemu-riscv64",
        "-L",
        "/usr/riscv64-linux-gnu",
        program_path,
        *args,
    ]

    try:
        env = os.environ.copy()
        env["QEMU_LD_PREFIX"] = "/usr/riscv64-linux-gnu"

        result = subprocess.run(cmd, capture_output=True, text=True, check=True, env=env)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        pytest.fail(f"Program exited with error: {e.stderr}")


@pytest.mark.parametrize("program_name", TEST_PROGRAMS.keys())
def test_program_functionality(program_name):
    """
    Tests program functionality after watermark insertion.

    :param program_name: Name of the program to test
    :type program_name: str
    :raises: pytest.skip if program not found
    :raises: AssertionError if functionality is broken
    """
    original_program = EXAMPLE_BINS_DIR / program_name
    watermarked_program = EXAMPLE_BINS_DIR / f"{Path(program_name).stem}.watermarked.elf"

    if not original_program.exists():
        pytest.skip(f"Test program {program_name} not found")

    test_data = TEST_PROGRAMS[program_name]

    if program_name == "cat.elf":
        test_file = PROJECT_ROOT / "test.txt"
        test_file.write_text("test content")

    try:
        watermarker = get_strategy("EQ_INSTR")()
        service = WatermarkService(str(original_program), watermarker)

        available_bits = service.get_capacity()
        max_chars = available_bits // 8

        truncated_message = SECRET_MESSAGE[:max_chars]

        service.encode(truncated_message.encode(), dst=str(watermarked_program))

        assert watermarked_program.exists(), "Watermarked file was not created"

        output = run_qemu_test(watermarked_program, test_data["args"])

        if "expected_output" in test_data:
            assert output == test_data["expected_output"], (
                f"Invalid program output for {program_name}. Expected: {test_data['expected_output']}, "
                f"got: {output}"
            )
        elif "expected_output_check" in test_data:
            assert test_data["expected_output_check"](output), (
                f"Output check failed for program {program_name}"
            )

    finally:
        if watermarked_program.exists():
            watermarked_program.unlink()
        if program_name == "cat.elf" and (PROJECT_ROOT / "test.txt").exists():
            (PROJECT_ROOT / "test.txt").unlink()
