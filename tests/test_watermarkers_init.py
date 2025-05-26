import pytest

from watermark_framework.watermarkers import (
    Watermarker,
    get_available_strategies,
    get_strategy,
    get_watermarkers,
)
from watermark_framework.watermarkers.eq_instr.module import EquivalentInstructionWatermarker


def test_get_available_strategies():
    """Test getting list of available strategies."""
    strategies = get_available_strategies()
    assert isinstance(strategies, list)
    assert "EQ_INSTR" in strategies
    assert len(strategies) > 0


def test_get_strategy():
    """Test getting strategy by name."""
    # Test getting existing strategy
    strategy = get_strategy("EQ_INSTR")
    assert strategy == EquivalentInstructionWatermarker

    # Test getting non-existent strategy
    with pytest.raises(ValueError, match="Unknown strategy"):
        get_strategy("NON_EXISTENT")


def test_get_watermarkers():
    """Test getting dictionary of available watermarkers."""
    watermarkers = get_watermarkers()
    assert isinstance(watermarkers, dict)
    assert "EQ_INSTR" in watermarkers
    assert watermarkers["EQ_INSTR"] == EquivalentInstructionWatermarker


def test_duplicate_method_name():
    """Test detection of duplicate METHOD_NAME in watermarkers."""
    class DuplicateWatermarker(Watermarker):
        METHOD_NAME = "EQ_INSTR"
        SUPPORTED_ARCHS = ["x86_64"]

        def get_nbits(self, section):
            return 0

        def encode(self, section, message):
            return section

        def decode(self, section):
            return b""

    with pytest.raises(ValueError, match="Duplicate METHOD_NAME"):
        get_watermarkers()
