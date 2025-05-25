import argparse
import sys
import os
from watermark_framework import WatermarkService
from watermark_framework.watermarkers import get_available_strategies, get_strategy

def parse_arguments():
    parser = argparse.ArgumentParser(description="Watermarking CLI for ELF binaries.")
    parser.add_argument("binary", nargs="?", help="Path to the ELF binary file.")
    parser.add_argument("-s", "--strategy", help="Watermarking strategy to use.")
    parser.add_argument("-e", "--encode", help="Message to encode into the binary.")
    parser.add_argument("-d", "--decode", help="Decode a message from the binary.", action="store_true")
    parser.add_argument("-c", "--capacity", help="Check the encoding capacity in bits.", action="store_true")
    parser.add_argument("-o", "--output", help="Output file path for encoded binary (default: <binary>.patched).")
    parser.add_argument("-l", "--list", help="List all built-in watermarkers.", action="store_true")
    return parser.parse_args()

def list_strategies():
    print("Available watermarking strategies:")
    for s in get_available_strategies():
        print(f" - {s}")
    sys.exit(0)

def error(msg, exit_code=1):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(exit_code)

def error_with_strategies(msg):
    print(f"Error: {msg}", file=sys.stderr)
    for s in get_available_strategies():
        print(f" - {s}", file=sys.stderr)
    sys.exit(1)

def validate_file(path):
    if not os.path.exists(path):
        error(f"File not found: {path}")
    if not os.path.isfile(path):
        error(f"Not a file: {path}")
    if not os.access(path, os.R_OK):
        error(f"File not readable: {path}")

def init_service(binary, strategy_name):
    available = get_available_strategies()
    if strategy_name not in available:
        error(f"Unknown strategy '{strategy_name}'. Available strategies: {', '.join(available)}")
    try:
        StrategyClass = get_strategy(strategy_name)
        return WatermarkService(binary, StrategyClass())
    except Exception as e:
        error(f"Error initializing service: {e}")

def handle_encode(service, message, output_path):
    try:
        result = service.encode(message.encode(), dst=output_path)
        print(f"Encoding successful. Modified binary saved to {result}")
        sys.exit(0)
    except Exception as e:
        error(f"Operation failed: {e}")

def handle_decode(service):
    try:
        msg = service.decode()
        print(f"Decoded message: {msg.decode()}")
        sys.exit(0)
    except Exception as e:
        error(f"Operation failed: {e}")

def handle_capacity(service):
    try:
        cap = service.get_capacity()
        print(f"Available encoding capacity: {cap} bits")
        sys.exit(0)
    except Exception as e:
        error(f"Operation failed: {e}")

def main():
    args = parse_arguments()

    if args.list:
        list_strategies()

    if not args.binary:
        error("Binary file path is required when not using -l.")

    validate_file(args.binary)

    ops = bool(args.encode or args.decode or args.capacity)
    if ops and not args.strategy:
        error_with_strategies("No strategy specified for -s.")

    service = None
    if args.strategy:
        service = init_service(args.binary, args.strategy)

    if args.encode:
        handle_encode(service, args.encode, args.output)
    if args.decode:
        handle_decode(service)
    if args.capacity:
        handle_capacity(service)

    error("No operation specified. Use -e, -d, -c, or -l.")

if __name__ == "__main__":
    main()
