from riscv_watermark.watermarkers.interface import Watermarker


class AddiWatermarker(Watermarker):
    def encode(self, src_filename, message):
        pass

    def decode(self, src_filename):
        pass

    def get_nbits(self, src_filename):
        pass
