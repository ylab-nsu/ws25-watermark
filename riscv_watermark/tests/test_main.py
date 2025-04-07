import logging
import os

import pytest

from riscv_watermark.main import (
    decode_message,
    encode_message,
    get_available_bits,
    parse_arguments,
    validate_file,
)
from riscv_watermark.utils import calculate_file_hash
from riscv_watermark.watermarkers.factory import fget_watermarker

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

SECRET_MESSAGE = "This file has been signed with ws25-watermark"


@pytest.mark.parametrize(
    "filepath",
    [
        "example_bins/sqlite3.elf",
        "example_bins/example.elf",
    ],
)
def test_encode_decode_message(filepath):
    validate_file(filepath)

    directory = os.path.dirname(filepath)
    basic_filepath = os.path.splitext(filepath)[0]
    patched_filepath = os.path.join(directory, f"{os.path.basename(basic_filepath)}.patched")

    watermarker = fget_watermarker("equal_funcs")

    available_bits = watermarker.get_nbits(filepath)
    max_letters = available_bits // 8
    truncated_message = SECRET_MESSAGE[:max_letters]
    logger.info(f"Message to encode: '{truncated_message}' (Length: {len(truncated_message)})")

    try:
        original_hash = calculate_file_hash(filepath)

        encode_message(filepath, [watermarker], truncated_message, patched_filepath)

        new_hash = calculate_file_hash(patched_filepath)

        if original_hash != new_hash:
            logger.info("File has been modified.")
        else:
            logger.info("File has not been modified.")

        logger.info(f"Decoding message from file: {patched_filepath}")

        decoded_dict = decode_message(patched_filepath, [watermarker])

        if not decoded_dict:
            logger.error(f"Decoded message dictionary is empty: {decoded_dict}")
            pytest.fail("Decoding failed: No message returned.")

        decoded_message = next(iter(decoded_dict.values()), "").rstrip("\x00")

        assert decoded_message == truncated_message, f"Decoded message doesn't match: '{decoded_message}'"
    except Exception as e:
        pytest.fail(f"Test failed due to error: {e}")
    finally:
        if os.path.exists(patched_filepath):
            os.remove(patched_filepath)
            logger.info(f"Removed patched file: {patched_filepath}")


@pytest.mark.parametrize(
    "filepath",
    [
        "example_bins/sqlite3.elf",
        "example_bins/example.elf",
    ],
)
def test_get_available_bits(filepath):
    logger.info(f"Starting test for get_available_bits with file: {filepath}")

    try:
        validate_file(filepath)
        watermarker = fget_watermarker("equal_funcs")
        available_bits = get_available_bits(filepath, [watermarker])

        for watermarker_name, capacity in available_bits.items():
            logger.info(f"Available bits for {watermarker_name}: {capacity} ({capacity // 8} characters)")

        assert all(capacity > 0 for capacity in available_bits.values()), (
            "No available bits for watermarking."
        )

        logger.info(f"Test passed for get_available_bits with file: {filepath}")
    except Exception as e:
        pytest.fail(f"Test failed due to error: {e}")


def test_parse_arguments(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "riscv-watermark",
            "-e",
            "Hello",
            "-m",
            "method_name",
            "-d",
            "-g",
            "-o",
            "output.txt",
            "elf_file",
        ],
    )

    args = parse_arguments()

    assert args.encode == "Hello"
    assert args.methods == "method_name"
    assert args.decode is True
    assert args.get_nbits is True
    assert args.output == "output.txt"
    assert args.filename == "elf_file"
