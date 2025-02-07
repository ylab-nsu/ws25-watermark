import logging
import sys
from riscv_watermark.watermarkers.interface import Watermarker
logger = logging.getLogger(__name__)

class Decoder:
    def __init__(self, patched_filename: str, methods: lsit[Watermarker]):
        self.patched_filename = patched_filename
        self.methods = methods

    def decode(self):
        for watermarker in self.methods:
            decoded = watermarker.decode(self.patched_filename)
            return decoded


