from riscv_watermark.watermarkers.interface import Watermarker
from .exceptions import NoSizeException
from .watermarkers import fget_watermarker


class Encoder:
    def __init__(self, src_filename: str, methods: list[Watermarker],message:str):
        self.src_filename = src_filename
        self.methods = methods
        self.message: str = message

        #calculate total size in bits available to encode in ELF
        self.sizes = [watermarker.get_nbits(self.src_filename) for watermarker in self.methods]


    def can_encode(self):
        return sum(self.sizes) / 8 >= len(self.message.encode('utf-8'))

    def encode(self):
        if not self.can_encode():
            raise NoSizeException("Not enough size to encode")
        for watermarker in self.methods:
            watermarker.encode(self.src_filename)