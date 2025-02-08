from riscv_watermark.watermarkers.eq_instr_watermarker.module import \
    EquivalentInstructionWatermarker
from riscv_watermark.watermarkers.stack_watermarker.module import \
    StackWatermarker


def fget_watermarker(name: str):
    if name == 'stack':
        return StackWatermarker()
    if name == 'zerofier':
        return EquivalentInstructionWatermarker()

    return None
