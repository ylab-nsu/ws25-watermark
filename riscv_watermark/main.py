import argparse
import logging
import os
import sys
from typing import Dict, List, Optional

from elftools.elf.elffile import ELFFile

from riscv_watermark.decoder import Decoder
from riscv_watermark.encoder import Encoder
from riscv_watermark.watermarkers.factory import fget_watermarker, get_available_methods
from riscv_watermark.watermarkers.interface import Watermarker

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s", datefmt="%M:%S"
)
logger = logging.getLogger(__name__)


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.

    :return: Parsed arguments
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        prog="RISC-V Watermarker",
        description="Encode and get messages from RISC-V binaries",
    )
    parser.add_argument("-e", "--encode", type=str, help="Message to encode in binary")
    parser.add_argument("-m", "--methods", type=str, help="Specify methods to use")
    parser.add_argument("-d", "--decode", action="store_true", help="Decode message from binary")
    parser.add_argument(
        "-g",
        "--get-nbits",
        action="store_true",
        help="Print amount of bits available to hide in binary",
    )
    parser.add_argument("-o", "--output", type=str, help="Output file path (default: filename.patched)")
    parser.add_argument("filename", help="Path to the binary file")

    return parser.parse_args()


def get_watermarkers(methods_str: Optional[str]) -> List[Watermarker]:
    """
    Convert comma-separated method names to watermarker instances.

    :param methods_str: Comma-separated string of method names
    :type methods_str: str
    :return: List of watermarker instances
    """
    if not methods_str:
        logger.error("No methods specified. Use -m/--methods to specify watermarking methods.")
        sys.exit(1)

    methods = methods_str.split(",")
    watermarkers = [fget_watermarker(method) for method in methods]

    if None in watermarkers:
        invalid_methods = [m for i, m in enumerate(methods) if watermarkers[i] is None]
        logger.error(f"Unsupported watermarking method(s): {', '.join(invalid_methods)}")
        available_methods = get_available_methods()
        logger.info(f"Available methods: {', '.join(available_methods)}")
        sys.exit(1)

    return watermarkers


def get_available_bits(filename: str, watermarkers: List[Watermarker]) -> Dict[str, int]:
    """
    Logs the number of bits available for hiding data in the binary file for each watermarker.
    Returns dictionary of watermarker names and available bits.

    :param filename: Path to the binary file
    :type filename: str
    :param watermarkers: List of watermarker instances
    :type watermarkers: List[Watermarker]
    :return: Number of bits available for hiding data
    :rtype: int
    """
    try:
        encoder = Encoder(filename, watermarkers, "")
        for watermarker_name, capacity in encoder.capacities.items():
            logger.info(f"Available bits for {watermarker_name}: {capacity} ({capacity // 8} characters)")
        return encoder.capacities
    except Exception as e:
        logger.error(f"Error calculating available bits: {e}")
        sys.exit(1)


def validate_file(filename: str) -> None:
    """
    Validate that the file exists and is readable.

    :param filename: Path to the file
    :type filename
    """
    if not os.path.exists(filename):
        logger.error(f"File not found: {filename}")
        sys.exit(1)

    if not os.path.isfile(filename):
        logger.error(f"Not a file: {filename}")
        sys.exit(1)

    if not os.access(filename, os.R_OK):
        logger.error(f"File not readable: {filename}")
        sys.exit(1)


def encode_message(
    filename: str, watermarkers: List[Watermarker], message: str, output_file: Optional[str] = None
) -> None:
    """
    Encode a message in the binary file.

    :param filename: Path to the binary file
    :type filename: str
    :param watermarkers: List of watermarker instances
    :type watermarkers: List[Watermarker]
    :param message: Message to encode
    :type message: str
    :param output_file: Path to the output file
    :type output_file: Optional[str]
    """
    try:
        encoder = Encoder(filename, watermarkers, message)
        logger.info(f"Available max bit capacity: {encoder.max_capacity} bits")
        logger.info(f"Message size: {len(message) * 8} bits")

        new_data = encoder.encode()
        new_filename = output_file if output_file else f"{filename}.patched"
        logger.info(f"Creating patched file: {new_filename}")

        with open(filename, "rb") as source_file:
            original_data = source_file.read()
            source_file.seek(0)
            elf_file = ELFFile(source_file)
            text_section = elf_file.get_section_by_name(".text")
            if not text_section:
                logger.error("Could not find .text section in ELF file")
                sys.exit(1)

            text_offset = text_section["sh_offset"]

        with open(new_filename, "wb") as target_file:
            target_file.write(original_data)
            target_file.seek(text_offset)
            target_file.write(new_data)

        logger.info(f"Message successfully encoded in {new_filename}")

    except Exception as e:
        logger.error(f"Encoding failed: {e}")
        sys.exit(1)


def decode_message(filename: str, watermarkers: List[Watermarker]) -> Dict[str, str]:
    """
    Decode a message from the binary file.
    If multiple methods are used, the message from each method is returned as a dictionary.

    :param filename: Path to the binary file
    :type filename: str
    :param watermarkers: List of watermarker instances
    :type watermarkers: List[Watermarker]
    :return Dictionary of method names and decoded messages
    :rtype Dict[str, str]
    """
    try:
        decoder = Decoder(filename, watermarkers)
        decoded_dict = decoder.decode()

        if len(decoded_dict) == 1:
            decoded_message = next(iter(decoded_dict.values()))
            print(f"Decoded message: {decoded_message}")
        else:
            for method, message in decoded_dict.items():
                print(f"Decoded message from {method}: {message}")

        logger.info("Message successfully decoded")
        return decoded_dict

    except Exception as e:
        logger.error(f"Decoding failed: {e}")
        raise RuntimeError(f"Decoding failed: {e}")


def main() -> None:
    """
    CLI entry point for the RISC-V Watermarker.
    """
    args = parse_arguments()

    validate_file(args.filename)

    if args.encode and args.decode:
        logger.error("Cannot encode and decode at the same time")
        sys.exit(1)

    watermarkers = get_watermarkers(args.methods)

    if args.get_nbits:
        get_available_bits(args.filename, watermarkers)

    elif args.encode:
        encode_message(args.filename, watermarkers, args.encode, args.output)

    elif args.decode:
        decode_message(args.filename, watermarkers)

    else:
        logger.error("No operation specified. Use -e, -d, or -g")
        sys.exit(1)


if __name__ == "__main__":
    main()
