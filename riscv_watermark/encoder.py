import logging
import sys
from itertools import cycle

from riscv_watermark.watermarkers.interface import Watermarker

from riscv_watermark.exceptions import NoSizeException

logger = logging.getLogger(__name__)


class Encoder:
    def __init__(
        self, src_filename: str, methods: list[Watermarker], message: str
    ):
        self.src_filename = src_filename
        self.methods = methods
        self.message: str = message
        # calculate total size in bits available to encode in ELF
        self.sizes = [
            watermarker.get_nbits(self.src_filename)
            for watermarker in self.methods
        ]

    def total_size(self):
        return sum(self.sizes)

    def can_encode(self):
        return self.total_size() / 8 >= len(self.message.encode('utf-8'))
        # тут на самом деле не 8. Значение может
        # варьироваться в зависимости от количества замен

    def encode(self) -> bytes:
#        if not self.can_encode():
#            logger.info('Not enough size to encode')
#            raise NoSizeException('')
        new_data = b''
        for watermarker in self.methods:
            number = watermarker.get_nbits(self.src_filename)
            number //= 8
            c = list(self.message)
            msg_len = len(c)
            if number < 1:
                logger.info("low amount of codeable bits")  
            if number < msg_len:
                logger.info("Not enough bits to encode the whole message")
            if number > msg_len:
                for i in range(number - msg_len):
                    c.append(' ') #пока так
            new_data = watermarker.encode(self.src_filename, c)
        if new_data != b'':
            return new_data
        else:
            logger.info('encoding failed')
            sys.exit()

    def getnbits(self):
        for watermarker in self.methods:
            return watermarker.get_nbits(self.src_filename)
