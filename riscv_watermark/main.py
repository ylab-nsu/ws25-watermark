import argparse

from .encoder import Encoder
from .utils import parse_methods
from .watermarkers.fabric import fget_watermarker


def main():
    parser = argparse.ArgumentParser(
        prog='RISC-V Watermarker',
        description='Encode and get messages from RISC-V binaries'
    )
    parser.add_argument('-e', '--encode', type=str, help="Message to encode in binary")
    parser.add_argument('-m', '--methods', type=str, help="Specify methods to use")
    parser.add_argument('-d', '--decode', action='store_true')
    parser.add_argument('--stack', action='store_true', help="Use stack manipulations in encode/decode")
    parser.add_argument('--addi', action='store_true', help="Use addi/add replacement in encode/decode")
    parser.add_argument('filename')
    args = parser.parse_args()

    if args.encode and args.decode:
        print("Specify method (encode or decode)")
        return


    methods = parse_methods(args.methods)
    methods = [fget_watermarker(x) for x in methods]
    if None in methods:
        print("Unsupported method detected")
    if args.encode:
        encoder = Encoder(args.filename, methods)

    if args.decode:
        pass
