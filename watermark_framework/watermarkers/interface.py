from abc import ABC, abstractmethod

from watermark_framework.architecture import Architecture
from watermark_framework.io import TextSection


class Watermarker(ABC):
    METHOD_NAME: str
    SUPPORTED_ARCHS: set[Architecture]

    @abstractmethod
    def get_nbits(self, section: TextSection) -> int:
        """Return the maximum number of message bits that can be encoded."""
        pass

    @abstractmethod
    def encode(self, section: TextSection, message: bytes) -> bytes:
        """Encode the message into the section and return the modified binary data."""
        pass

    @abstractmethod
    def decode(self, section: TextSection) -> bytes:
        """Decode the message from the section and return it as bytes."""
        pass
