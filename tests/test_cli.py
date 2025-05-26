import os
from pathlib import Path
import subprocess

import pytest

from watermark_framework import WatermarkService
from watermark_framework.watermarkers import get_strategy

PROJECT_ROOT = Path(__file__).parent.parent
EXAMPLE_BINS_DIR = PROJECT_ROOT / "example_bins"

def run_cli_command(args: list[str]) -> tuple[int, str, str]:
    """
    Runs a CLI command and returns its result.

    Args:
        args: List of command line arguments.

    Returns:
        tuple: (return code, stdout, stderr)
    """
    cmd = ["python", "-m", "watermark_framework.cli.main", *args]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

def test_list_strategies():
    """Test the command to list available strategies."""
    returncode, stdout, stderr = run_cli_command(["--list"])
    assert returncode == 0
    assert "Available watermarking strategies:" in stdout
    assert "EQ_INSTR" in stdout

def test_missing_binary():
    """Test handling of missing binary file."""
    returncode, stdout, stderr = run_cli_command([])
    assert returncode == 1
    assert "Error: Binary file path is required" in stderr

def test_nonexistent_binary():
    """Test handling of non-existent binary file."""
    returncode, stdout, stderr = run_cli_command(["nonexistent.elf"])
    assert returncode == 1
    assert "Error" in stderr

def test_invalid_strategy():
    """Test handling of invalid strategy."""
    test_bin = EXAMPLE_BINS_DIR / "echo.elf"
    if not test_bin.exists():
        pytest.skip("Test binary not found")

    returncode, stdout, stderr = run_cli_command([str(test_bin), "-s", "INVALID_STRATEGY"])
    assert returncode == 1
    assert "Unknown strategy" in stderr

def test_encode_decode_flow(tmp_path):
    """Test the complete encoding and decoding cycle."""
    test_bin = EXAMPLE_BINS_DIR / "echo.elf"
    if not test_bin.exists():
        pytest.skip("Test binary not found")

    # Test encoding
    output_path = str(tmp_path / "output.elf")
    message = "Test message"
    returncode, stdout, stderr = run_cli_command([
        str(test_bin),
        "-s", "EQ_INSTR",
        "-e", message,
        "-o", output_path
    ])
    assert returncode == 0
    assert "Encoding successful" in stdout
    assert os.path.exists(output_path)

    # Test decoding
    returncode, stdout, stderr = run_cli_command([
        output_path,
        "-s", "EQ_INSTR",
        "-d"
    ])
    assert returncode == 0
    assert message in stdout

def test_capacity_check():
    """Test capacity check command."""
    test_bin = EXAMPLE_BINS_DIR / "echo.elf"
    if not test_bin.exists():
        pytest.skip("Test binary not found")

    returncode, stdout, stderr = run_cli_command([
        str(test_bin),
        "-s", "EQ_INSTR",
        "-c"
    ])
    assert returncode == 0
    assert "Available encoding capacity:" in stdout
    assert "bits" in stdout

def test_missing_operation():
    """Test handling of missing operation."""
    test_bin = EXAMPLE_BINS_DIR / "echo.elf"
    if not test_bin.exists():
        pytest.skip("Test binary not found")

    returncode, stdout, stderr = run_cli_command([
        str(test_bin),
        "-s", "EQ_INSTR"
    ])
    assert returncode == 1
    assert "No operation specified" in stderr
