import logging
from typing import Dict

from riscv_watermark.exceptions import DecodingError
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
        res = {}

        if len(self._methods) == 1:
            try:
                decoded = self._methods[0].decode(self._patched_filename)
                if decoded is None:
                    raise DecodingError("Method is not implemented")
                res[self._methods[0].__class__.__name__] = decoded.rstrip()
            except Exception as e:
                logger.error(f"{self._methods[0].__class__.__name__} failed: {e}")
        else:
            for watermarker in self._methods:
                try:
                    decoded = watermarker.decode(self._patched_filename)
                    if decoded is None:
                        raise DecodingError("Method is not implemented")
                    watermarker_name = watermarker.__class__.__name__
                    res[watermarker_name] = decoded.rstrip()
                except Exception as e:
                    logger.warning(f"{watermarker_name} failed: {e}")
                    continue
        if not res:
            raise DecodingError("Failed to decode with all methods")
        else:
            return res
