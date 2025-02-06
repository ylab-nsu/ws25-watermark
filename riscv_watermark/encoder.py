from riscv_watermark.watermarkers.interface import Watermarker
from .watermarkers import fget_watermarker


class Encoder:
    def __init__(self, src_filename: str, methods: list[Watermarker],message:str):
        self.src_filename = src_filename
        self.methods = methods
        self.message: str = message
        self.sizes = [watermarker.get_nbits(self.src_filename) for watermarker in self.methods]


    def can_encode(self):
        return sum(self.sizes) / 8 >= len(self.message.encode('utf-8'))

    def encode(self):
        for watermarker in self.methods:
            watermarker.encode(self.src_filename)