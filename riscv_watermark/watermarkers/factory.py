from riscv_watermark.watermarkers.stack_watermarker.module import StackWatermarker
from riscv_watermark.watermarkers.zerofier_watermarker.module import ZerofierWatermarker


def fget_watermarker(name: str):
    if name == 'stack':
        return StackWatermarker()
    if name == 'zerofier':
        return ZerofierWatermarker()

    return None
