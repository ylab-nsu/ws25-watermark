import logging
import os
import subprocess

import pytest

from riscv_watermark.main import encode_message
from riscv_watermark.watermarkers.factory import fget_watermarker

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TEST_PROGRAMS = {
    "echo.elf": {"args": ["Hello, World!"], "expected_output": "Hello, World!"},
    "cat.elf": {"args": ["test.txt"], "expected_output": "test content"},
    "ls.elf": {"args": [], "expected_output_check": lambda x: len(x.split("\n")) > 0},
}

SECRET_MESSAGE = "This file has been signed with ws25-watermark"


def run_qemu_test(program_path, args):
    """
    Runs a program in QEMU and returns its output.

    :param program_path: Path to the executable file
    :type program_path: str
    :param args: List of command line arguments
    :type args: List[str]
    :return: Program output
    :rtype: str
    :raises: pytest.fail if program exits with error
    """

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
    original_program = os.path.join("example_bins", program_name)
    watermarked_program = os.path.join("example_bins", f"{os.path.splitext(program_name)[0]}.watermarked.elf")

    if not os.path.exists(original_program):
        pytest.skip(f"Test program {program_name} not found")

    test_data = TEST_PROGRAMS[program_name]

    if program_name == "cat.elf":
        with open("test.txt", "w") as f:
            f.write("test content")

    try:
        watermarker = fget_watermarker("eq_instr")

        available_bits = watermarker.get_nbits(original_program)
        max_chars = available_bits // 8

        truncated_message = SECRET_MESSAGE[:max_chars]
        logger.info(f"Available capacity: {available_bits} bits ({max_chars} chars)")
        logger.info(f"Message to encode: '{truncated_message}' (Length: {len(truncated_message)})")

        encode_message(original_program, [watermarker], truncated_message, watermarked_program)

        assert os.path.exists(watermarked_program), "Watermarked file was not created"

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
        if os.path.exists(watermarked_program):
            os.remove(watermarked_program)
        if program_name == "cat.elf" and os.path.exists("test.txt"):
            os.remove("test.txt")
