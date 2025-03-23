from riscv_watermark.watermarkers.interface import Watermarker


class StackWatermarker(Watermarker):
    def encode(self, text_data, message):
        pass

    def decode(self, text_data):
        pass

    def get_nbits(self, text_data):
        return 0
