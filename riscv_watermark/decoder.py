import logging
from typing import Dict

from riscv_watermark.watermarkers.interface import Watermarker
from riscv_watermark.exceptions import DecodingError

logger = logging.getLogger(__name__)


class Decoder:
    """
    Handles the decoding of messages from binary files using watermarking techniques.
    """
    def __init__(self, patched_filename: str, methods: list[Watermarker]):
        self.__patched_filename = patched_filename
        self.__methods = methods

    def decode(self) -> Dict[str, str]:
        """
        Decode the message from the binary file using the watermarking methods.
        If multiple methods are used, the message from each method is returned as a dictionary.
        
        :return: Dictionary of method names and decoded messages
        :rtype: Dict[str, str]
        """
        res = {}
        
        if len(self.__methods) == 1:
            try:
                decoded = self.__methods[0].decode(self.__patched_filename)
                if decoded == None:
                    raise DecodingError("Method is not implemented")
                res[self.__methods[0].__class__.__name__] = decoded.rstrip()
            except Exception as e:
                logger.error(f"{self.__methods[0].__class__.__name__} failed: {e}")
        else:
            for watermarker in self.__methods:
                try:
                    decoded = watermarker.decode(self.__patched_filename)
                    if decoded == None:
                        raise DecodingError("Method is not implemented")
                    res[watermarker.__class__.__name__] = decoded.rstrip()
                except Exception as e:
                    logger.warning(f"{watermarker.__class__.__name__} failed: {e}")
                    continue
        if not res:
            raise DecodingError("Failed to decode with all methods")
        else:
            return res
