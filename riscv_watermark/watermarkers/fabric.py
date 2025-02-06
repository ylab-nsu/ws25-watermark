from . import *

def fget_watermarker(name: str):
    if name == "addi":
        return AddiWatermarker()
    if name == "stack":
        return StackWatermarker()
    if name == "zerofier":
        return ZerofierWatermarker()

    return None