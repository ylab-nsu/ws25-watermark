from itertools import cycle
import logging
import sys
from riscv_watermark.watermarkers.interface import Watermarker
logger = logging.getLogger(__name__)
from .exceptions import NoSizeException


class Encoder:
    def __init__(self, src_filename: str, methods: list[Watermarker], message: str):
        self.src_filename = src_filename
        self.methods = methods
        self.message: str = message
        # calculate total size in bits available to encode in ELF
        self.sizes = [
            watermarker.get_nbits(self.src_filename) for watermarker in self.methods
        ]

    def total_size(self):
        return sum(self.sizes)

    def can_encode(self):
        return self.total_size() / 8 >= len(self.message.encode("utf-8"))
        # тут на самом деле не 8. Значение может варьироваться в зависимости от количества замен

    def encode(self) -> bytes:
        if not self.can_encode():
            logger.info("Not enough size to encode")
            raise NoSizeException("")
        new_data = ''
        for watermarker in self.methods:
            c = [i for i, j in zip(cycle('nonsense'), range(watermarker.get_nbits))]
            new_data = watermarker.encode(self.src_filename, c)
        if new_data != '':
            return new_data
        else:
            logger.info("encoding failed")
            sys.exit()  
