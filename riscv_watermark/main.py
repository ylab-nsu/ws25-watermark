import argparse
import logging
import os
import sys
from typing import List, Optional

from elftools.elf.elffile import ELFFile

from riscv_watermark.decoder import Decoder
from riscv_watermark.encoder import Encoder
from riscv_watermark.watermarkers.factory import fget_watermarker, get_available_methods
from riscv_watermark.watermarkers.interface import Watermarker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
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


def get_available_bits(filename: str, watermarkers: List[Watermarker]) -> int:
    """
    Calculate the number of bits available for hiding data.
    
    :param filename: Path to the binary file
    :type filename: str
    :param watermarkers: List of watermarker instances
    :type watermarkers: List[Watermarker]
    :return: Number of bits available for hiding data
    :rtype: int
    """
    try:
        encoder = Encoder(filename, watermarkers, "")
        return encoder.get_nbits()
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
        
def encode_message(filename: str, watermarkers: List[Watermarker], message: str, output_file: Optional[str] = None) -> None:
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
        logger.info(f"Available bit capacity: {encoder.get_nbits()} bits")
        logger.info(f"Message size: {len(message) * 8} bits")
            
        new_data = encoder.encode()
        new_filename = output_file if output_file else f"{filename}.patched"
        logger.info(f"Creating patched file: {new_filename}")
        
        try:
            with open(filename, "rb") as source_file:
                original_data = source_file.read()
                source_file.seek(0)
                elf_file = ELFFile(source_file)
                text_section = elf_file.get_section_by_name(".text")
                if not text_section:
                    logger.error("Could not find .text section in ELF file")
                    sys.exit(1)
                    
                text_addr = text_section["sh_addr"]
                
            with open(new_filename, "wb") as target_file:
                target_file.write(original_data)
                target_file.seek(text_addr)
                target_file.write(new_data)
                
            logger.info(f"Message successfully encoded in {new_filename}")
                
        except IOError as e:
            logger.error(f"File operation failed: {e}")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Encoding failed: {e}")
        sys.exit(1)


def decode_message(filename: str, watermarkers: List[Watermarker]) -> str:
    """
    Decode a message from the binary file.
    
    :param filename: Path to the binary file
    :type filename: str
    :param watermarkers: List of watermarker instances
    :type watermarkers: List[Watermarker]
    """
    try:
        decoder = Decoder(filename, watermarkers)
        decoded_message = decoder.decode().rstrip()
        
        print(f"Decoded message: {decoded_message}")
        logger.info("Message successfully decoded")
        return decoded_message
    except Exception as e:
        logger.error(f"Decoding failed: {e}")
        sys.exit(1)


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
        bits = get_available_bits(args.filename, watermarkers)
        print(f"Available bits for watermarking: {bits}")
        print(f"Maximum message length (approx): {bits // 8} characters")
        
    elif args.encode:
        encode_message(args.filename, watermarkers, args.encode, args.output)
        
    elif args.decode:
        decode_message(args.filename, watermarkers)
        
    else:
        logger.error("No operation specified. Use -e, -d, or -g")
        sys.exit(1)


if __name__ == "__main__":
    main()