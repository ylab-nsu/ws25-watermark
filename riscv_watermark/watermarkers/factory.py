from .addi_watermarker.module import AddiWatermarker
from .stack_watermarker.module import StackWatermarker
from .zerofier_watermarker.module import ZerofierWatermarker


def fget_watermarker(name: str):
    if name == 'addi':
        return AddiWatermarker()
    if name == 'stack':
        return StackWatermarker()
    if name == 'zerofier':
        return ZerofierWatermarker()

    return None
