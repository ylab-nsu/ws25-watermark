import argparse
import logging

from .encoder import Encoder
from .watermarkers.factory import fget_watermarker

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        prog='RISC-V Watermarker',
        description='Encode and get messages from RISC-V binaries',
    )
    parser.add_argument(
        '-e', '--encode', type=str, help='Message to encode in binary'
    )
    parser.add_argument(
        '-m', '--methods', type=str, help='Specify methods to use'
    )
    parser.add_argument('-d', '--decode', action='store_true')
    parser.add_argument(
        '-g',
        '--get-nbits',
        action='store_true',
        help='Print amount of bits available to hide in binary',
    )
    parser.add_argument('filename')
    args = parser.parse_args()

    if args.encode and args.decode:
        print('Specify method (encode or decode)')
        return

    methods = args.methods.split(',')
    methods = [fget_watermarker(x) for x in methods]
    if None in methods:
        logger.info('Unsupported method detected')
        return
    if args.encode:
        encoder = Encoder(args.filename, methods, args.encode)
        logger.info(encoder.sizes)
        new_data = encoder.encode()
        new_filename = args.filename + '.patched'
        with open(new_filename, 'wb') as f:
            f.write(new_data)
    if args.decode:
        raise NotImplementedError
