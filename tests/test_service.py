import os
from pathlib import Path

import pytest

from watermark_framework.core.service import WatermarkService
from watermark_framework.watermarkers import get_strategy
from watermark_framework.watermarkers.interface import Watermarker


@pytest.fixture
def test_bin_path() -> str:
    """Returns path to a test binary file."""
    return str(Path(__file__).parent.parent / "example_bins" / "echo.elf")


@pytest.fixture
def service(test_bin_path: str) -> WatermarkService:
    """Returns a WatermarkService instance with a test binary."""
    return WatermarkService(test_bin_path)


def test_service_initialization(test_bin_path: str):
    """Test service initialization with and without strategy."""
    service = WatermarkService(test_bin_path)
    assert service._section is not None
    assert service._strategy is None

    strategy = get_strategy("EQ_INSTR")()
    service = WatermarkService(test_bin_path, strategy)
    assert service._section is not None
    assert service._strategy == strategy


def test_strategy_validation(service: WatermarkService):
    """Test strategy validation and setting."""
    strategy = get_strategy("EQ_INSTR")()

    service.set_strategy(strategy)
    assert service._strategy == strategy

    class InvalidStrategy(Watermarker):
        METHOD_NAME = "invalid"
        SUPPORTED_ARCHS = ["invalid_arch"]

        def get_nbits(self, section) -> int:
            return 0

        def encode(self, section, message: bytes) -> bytes:
            return b""

        def decode(self, section) -> bytes:
            return b""

    with pytest.raises(ValueError, match="does not support architecture"):
        service.set_strategy(InvalidStrategy())


def test_file_switching(service: WatermarkService, test_bin_path: str):
    """Test switching between files."""
    strategy = get_strategy("EQ_INSTR")()
    service.set_strategy(strategy)

    service.set_file(test_bin_path)
    assert service._section.src_path == test_bin_path

    with pytest.raises(FileNotFoundError):
        service.set_file("nonexistent.elf")


def test_capacity_calculation(service: WatermarkService):
    """Test capacity calculation with and without strategy."""
    strategy = get_strategy("EQ_INSTR")()

    with pytest.raises(ValueError, match="No strategy provided"):
        service.get_capacity()

    service.set_strategy(strategy)
    capacity = service.get_capacity()
    assert isinstance(capacity, int)
    assert capacity > 0

    capacity_with_explicit = service.get_capacity(strategy)
    assert capacity == capacity_with_explicit


def test_encode_decode(service: WatermarkService, tmp_path: Path):
    """Test message encoding and decoding."""
    strategy = get_strategy("EQ_INSTR")()
    service.set_strategy(strategy)

    message = b"Test"

    output_path = str(tmp_path / "output.elf")
    encoded_path = service.encode(message, dst=output_path)
    assert os.path.exists(encoded_path)

    service.set_file(encoded_path)
    decoded_message = service.decode()
    assert decoded_message.startswith(message)

    large_message = b"x" * (service.get_capacity() + 1)
    with pytest.raises(ValueError, match="exceeds section capacity"):
        service.encode(large_message)
