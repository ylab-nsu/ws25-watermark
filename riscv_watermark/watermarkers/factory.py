from riscv_watermark.watermarkers.eq_instr_watermarker.module import EquivalentInstructionWatermarker
from riscv_watermark.watermarkers.stack_watermarker.module import StackWatermarker

_WATERMARKERS = {
    "stack": StackWatermarker,
    "equal_funcs": EquivalentInstructionWatermarker,
}


def fget_watermarker(name: str):
    """
    Get a watermarker instance by name.

    :param name: Name of the watermarking method
    :type name: str
    :return: Watermarker instance
    :rtype: Watermarker
    """
    watermarker_class = _WATERMARKERS.get(name)
    if watermarker_class:
        return watermarker_class()
    return None


def get_available_methods() -> list:
    """
    Return a list of all available watermarking method names.

    :return: List of available watermarking method names
    """
    return list(_WATERMARKERS.keys())
