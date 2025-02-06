from riscv_watermark.watermarkers.interface import Watermarker


class AddiWatermarker(Watermarker):
    def encode(self, text_data, message):
        pass

    def decode(self, text_data):
        pass

    def get_nbits(self, text_data):
        pass
