import logging
from typing import Dict

from riscv_watermark.exceptions import WatermarkError
from riscv_watermark.watermarkers.interface import Watermarker

logger = logging.getLogger(__name__)


class Decoder:
    """
    Handles the decoding of messages from binary files using watermarking techniques.
    """

    def __init__(self, patched_filename: str, methods: list[Watermarker]):
        self._patched_filename = patched_filename
        self._methods = methods

    def decode(self) -> Dict[str, str]:
        """
        Decode the message from the binary file using the watermarking methods.
        If multiple methods are used, the message from each method is returned as a dictionary.

        :return: Dictionary of method names and decoded messages
        :rtype: Dict[str, str]
        """
        results: Dict[str, str] = {}
        for wm in self.__methods:
            name = wm.__class__.__name__
            try:
                decoded = wm.decode(self.__patched_filename)
                results[name] = decoded.rstrip()
            except WatermarkError as e:
                logger.warning(f"{name} failed: {e}")
            except Exception:
                logger.exception(f"Unexpected error in {name}")

        if not results:
            raise WatermarkError("Failed to decode with any watermarking method")
        return results
