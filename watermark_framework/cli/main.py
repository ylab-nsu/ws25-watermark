import argparse
import os
import sys

from watermark_framework import WatermarkService
from watermark_framework.watermarkers import get_available_strategies, get_strategy


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Watermarking CLI for ELF binaries.")
    parser.add_argument("binary", nargs="?", help="Path to the ELF binary file.")
    parser.add_argument("-s", "--strategy", help="Watermarking strategy to use.")
    parser.add_argument("-e", "--encode", help="Message to encode into the binary.")
    parser.add_argument("-d", "--decode", help="Decode a message from the binary.", action="store_true")
    parser.add_argument("-c", "--capacity", help="Check the encoding capacity in bits.", action="store_true")
    parser.add_argument("-o", "--output", help="Output file path for encoded binary (default: <binary>.patched).")
    parser.add_argument("-l", "--list", help="List all built-in watermarkers.", action="store_true")
    return parser.parse_args()


def list_strategies() -> None:
    print("Available watermarking strategies:")
    for s in get_available_strategies():
        print(f" - {s}")
    sys.exit(0)


def error(msg: str, exit_code: int = 1) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(exit_code)


def error_with_strategies(msg: str) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    for s in get_available_strategies():
        print(f" - {s}", file=sys.stderr)
    sys.exit(1)


def validate_file(path: str) -> None:
    if not os.path.exists(path):
        error(f"File not found: {path}")
    if not os.path.isfile(path):
        error(f"Not a file: {path}")
    if not os.access(path, os.R_OK):
        error(f"File not readable: {path}")


def init_service(binary: str, strategy_name: str) -> WatermarkService:
    available = get_available_strategies()
    if strategy_name not in available:
        error(f"Unknown strategy '{strategy_name}'. Available strategies: {', '.join(available)}")
    try:
        strategyclass = get_strategy(strategy_name)
        return WatermarkService(binary, strategyclass())
    except Exception as e:
        error(f"Error initializing service: {e}")
        # This line will never be reached due to error() calling sys.exit()
        # mypy needs it to understand the function always returns
        raise  # pragma: no cover


def handle_encode(service: WatermarkService, message: str, output_path: str | None) -> None:
    try:
        result = service.encode(message.encode(), dst=output_path)
        print(f"Encoding successful. Modified binary saved to {result}")
        sys.exit(0)
    except Exception as e:
        error(f"Operation failed: {e}")


def handle_decode(service: WatermarkService) -> None:
    try:
        msg = service.decode()
        print(f"Decoded message: {msg.decode()}")
        sys.exit(0)
    except Exception as e:
        error(f"Operation failed: {e}")


def handle_capacity(service: WatermarkService) -> None:
    try:
        cap = service.get_capacity()
        print(f"Available encoding capacity: {cap} bits")
        sys.exit(0)
    except Exception as e:
        error(f"Operation failed: {e}")


def main() -> None:
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
        assert service is not None, "Service should be initialized"
        handle_encode(service, args.encode, args.output)
    if args.decode:
        assert service is not None, "Service should be initialized"
        handle_decode(service)
    if args.capacity:
        assert service is not None, "Service should be initialized"
        handle_capacity(service)

    error("No operation specified. Use -e, -d, -c, or -l.")


if __name__ == "__main__":
    main()
