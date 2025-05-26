import pytest

from watermark_framework.watermarkers import (
    Watermarker,
    get_available_strategies,
    get_strategy,
    get_watermarkers,
)
from watermark_framework.architecture import Architecture


@pytest.fixture
def mock_watermarkers(monkeypatch):
    """Create mock watermarkers for testing with proper cleanup."""
    class TestWatermarker1(Watermarker):
        METHOD_NAME = "TEST_METHOD_1"
        SUPPORTED_ARCHS = {Architecture.X86_64}

        def get_nbits(self, section):
            return 8

        def encode(self, section, message):
            return b""

        def decode(self, section):
            return b"test"
    class TestWatermarker2(Watermarker):
        METHOD_NAME = "TEST_METHOD_2"
        SUPPORTED_ARCHS = {Architecture.RISCV}

        def get_nbits(self, section):
            return 16

        def encode(self, section, message):
            return b""

        def decode(self, section):
            return b"test2"

    monkeypatch.setattr(Watermarker, '__subclasses__', 
                       lambda: [TestWatermarker1, TestWatermarker2])
    
    return TestWatermarker1, TestWatermarker2


def test_get_available_strategies(mock_watermarkers):
    """Test getting list of available strategies."""
    strategies = get_available_strategies()
    assert isinstance(strategies, list)
    assert len(strategies) == 2
    assert "TEST_METHOD_1" in strategies
    assert "TEST_METHOD_2" in strategies


def test_get_strategy(mock_watermarkers):
    """Test getting strategy by name."""
    TestWatermarker1, TestWatermarker2 = mock_watermarkers
    
    strategy1 = get_strategy("TEST_METHOD_1")
    assert strategy1 == TestWatermarker1
    
    strategy2 = get_strategy("TEST_METHOD_2")
    assert strategy2 == TestWatermarker2

    with pytest.raises(ValueError, match="Unknown strategy"):
        get_strategy("NON_EXISTENT")


def test_get_watermarkers(mock_watermarkers):
    """Test getting dictionary of available watermarkers."""
    TestWatermarker1, TestWatermarker2 = mock_watermarkers
    
    watermarkers = get_watermarkers()
    assert isinstance(watermarkers, dict)
    assert len(watermarkers) == 2
    assert "TEST_METHOD_1" in watermarkers
    assert "TEST_METHOD_2" in watermarkers
    assert watermarkers["TEST_METHOD_1"] == TestWatermarker1
    assert watermarkers["TEST_METHOD_2"] == TestWatermarker2


def test_duplicate_method_name(monkeypatch):
    class DuplicateWatermarker1(Watermarker):
        METHOD_NAME = "DUPLICATE"
        SUPPORTED_ARCHS = {Architecture.X86_64}

        def get_nbits(self, section):
            return 0

        def encode(self, section, message):
            return b""

        def decode(self, section):
            return b""
    class DuplicateWatermarker2(Watermarker):
        METHOD_NAME = "DUPLICATE"
        SUPPORTED_ARCHS = {Architecture.RISCV}

        def get_nbits(self, section):
            return 0

        def encode(self, section, message):
            return b""

        def decode(self, section):
            return b""

    monkeypatch.setattr(Watermarker, '__subclasses__', 
                       lambda: [DuplicateWatermarker1, DuplicateWatermarker2])

    with pytest.raises(ValueError, match="Duplicate METHOD_NAME"):
        get_watermarkers()