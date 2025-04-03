import logging
import os

import pytest

from riscv_watermark.main import decode_message, encode_message
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
