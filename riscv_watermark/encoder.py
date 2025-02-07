from itertools import cycle

from riscv_watermark.watermarkers.interface import Watermarker

from .elf import ElfWorker
from .exceptions import NoSizeException


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

    def encode(self):
        if not self.can_encode():
            raise NoSizeException('Not enough size to encode')
        file = ElfWorker(self.src_filename)
        text_data = file.get_section_data('.text', 'rb')
        for watermarker in self.methods:
            c = [
                i
                for i, j in zip(
                    cycle('nonsense'), range(watermarker.get_nbits)
                )
            ]
            new_data = watermarker.encode(text_data, c)

        offset = file.text_offset
        size = file.text_size

        output_file = open(f'{self.src_filename}.patched', 'wb')

        with open(self.src_filename, 'rb') as input_file:
            output_file.write(input_file.read(offset))
            output_file.write(new_data)
            input_file.seek(offset + size)
            output_file.write(input_file.read())
            output_file.close()
