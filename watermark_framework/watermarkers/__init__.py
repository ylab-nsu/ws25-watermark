from watermark_framework.watermarkers.interface import Watermarker

#### Export watermarkers for importability:

from .eq_instr.module import EquivalentInstructionWatermarker

####

def get_available_strategies() -> list[str]:
    """Returns a list of available watermarking strategy names."""
    return list(get_watermarkers().keys())

def get_strategy(name) -> 'Watermarker':
    """Retrieves a Watermarker class by its METHOD_NAME."""
    watermarkers = get_watermarkers()
    if name not in watermarkers:
        raise ValueError(f"Unknown strategy: {name}. Available strategies: {', '.join(get_available_strategies())}")
    return watermarkers[name]

def get_watermarkers() -> dict[str, Watermarker]:
    """Dynamically discovers and returns a dictionary of available watermarkers."""
    watermarkers = {}
    for cls in Watermarker.__subclasses__():
        method_name = cls.METHOD_NAME
        if method_name in watermarkers:
            raise ValueError(f"Duplicate METHOD_NAME '{method_name}' found in watermarkers.")
        watermarkers[method_name] = cls
    return watermarkers
