import argparse
import logging
import sys
from elftools.elf.elffile import ELFFile
from riscv_watermark.encoder import Encoder
from riscv_watermark.decoder import Decoder
from riscv_watermark.watermarkers.factory import fget_watermarker

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

    methods = str(args.methods).split(',')
    methods = [fget_watermarker(x) for x in methods]
    if None in methods:
        logger.info('Unsupported method detected')
        return
    if args.get_nbits:
        enc = Encoder(args.filename, methods, '')
        nbits = enc.getnbits()
        print(nbits) #пока не работает
        return
    if args.encode:
        encoder = Encoder(args.filename, methods, args.encode)
        logger.info(encoder.sizes)
        logger.info('encoding finished')
        new_data = encoder.encode()
        new_filename = args.filename + '.patched'
        with open(new_filename, 'wb') as f, open(args.filename, 'rb') as fi:
            f.write(fi.read())
            fi.seek(0)
            elfi = ELFFile(fi)
            textaddr = elfi.get_section_by_name('.text')['sh_addr']
            f.seek(textaddr)
            f.write(new_data)
    if args.decode:
        decoded = Decoder(args.filename, methods)
        ret_str = decoded.decode()
        print(ret_str)
        logger.info('decoding finished')

if __name__ == '__main__':
    main()