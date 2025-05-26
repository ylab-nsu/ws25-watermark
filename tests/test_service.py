import os
from pathlib import Path

import pytest

from watermark_framework.core.service import WatermarkService
from watermark_framework.watermarkers import get_strategy
from watermark_framework.watermarkers.interface import Watermarker


@pytest.fixture
def test_bin_path():
    """Returns path to a test binary file."""
    return str(Path(__file__).parent.parent / "example_bins" / "echo.elf")


@pytest.fixture
def service(test_bin_path):
    """Returns a WatermarkService instance with a test binary."""
    return WatermarkService(test_bin_path)


def test_service_initialization(test_bin_path):
    """Test service initialization with and without strategy."""
    # Test initialization without strategy
    service = WatermarkService(test_bin_path)
    assert service._section is not None
    assert service._strategy is None

    # Test initialization with strategy
    strategy = get_strategy("EQ_INSTR")()
    service = WatermarkService(test_bin_path, strategy)
    assert service._section is not None
    assert service._strategy == strategy


def test_strategy_validation(service):
    """Test strategy validation and setting."""
    strategy = get_strategy("EQ_INSTR")()

    # Test setting valid strategy
    service.set_strategy(strategy)
    assert service._strategy == strategy

    # Test setting invalid strategy (mock)
    class InvalidStrategy(Watermarker):
        METHOD_NAME = "invalid"
        SUPPORTED_ARCHS = ["invalid_arch"]

        def get_nbits(self, section):
            return 0

        def encode(self, section, message):
            return section

        def decode(self, section):
            return b""

    with pytest.raises(ValueError, match="does not support architecture"):
        service.set_strategy(InvalidStrategy())


def test_file_switching(service, test_bin_path):
    """Test switching between files."""
    # Set initial strategy
    strategy = get_strategy("EQ_INSTR")()
    service.set_strategy(strategy)

    # Test switching to same file
    service.set_file(test_bin_path)
    assert service._section.src_path == test_bin_path

    # Test switching to invalid file
    with pytest.raises(FileNotFoundError):
        service.set_file("nonexistent.elf")


def test_capacity_calculation(service):
    """Test capacity calculation with and without strategy."""
    strategy = get_strategy("EQ_INSTR")()

    # Test without strategy
    with pytest.raises(ValueError, match="No strategy provided"):
        service.get_capacity()

    # Test with strategy
    service.set_strategy(strategy)
    capacity = service.get_capacity()
    assert isinstance(capacity, int)
    assert capacity > 0

    # Test with explicit strategy
    capacity_with_explicit = service.get_capacity(strategy)
    assert capacity == capacity_with_explicit


def test_encode_decode(service, tmp_path):
    """Test message encoding and decoding."""
    strategy = get_strategy("EQ_INSTR")()
    service.set_strategy(strategy)

    # Test message
    message = b"Test"

    # Test encoding
    output_path = str(tmp_path / "output.elf")
    encoded_path = service.encode(message, dst=output_path)
    assert os.path.exists(encoded_path)

    # Test decoding
    service.set_file(encoded_path)
    decoded_message = service.decode()
    assert decoded_message.startswith(message)

    # Test message too large
    large_message = b"x" * (service.get_capacity() + 1)
    with pytest.raises(ValueError, match="exceeds section capacity"):
        service.encode(large_message)
