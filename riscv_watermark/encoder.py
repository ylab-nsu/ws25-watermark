import logging
from typing import Dict, List, Optional

from riscv_watermark.exceptions import WatermarkError
from riscv_watermark.watermarkers.interface import Watermarker

logger = logging.getLogger(__name__)


class Encoder:
    """
    Handles the encoding of messages into binary files using watermarking techniques.

    This class coordinates the watermarking process using one or more watermarking
    methods to encode hidden messages into binary files.

    capacities: Dictionary of watermarking methods and their respective capacities.
    max_capacity: Maximum capacity of all watermarking methods.
    """

    def __init__(self, src_filename: str, methods: List[Watermarker], message: str):
        """
        Initialize the encoder with source file, watermarking methods, and message.

        :param src_filename: Path to the source binary file
        :type src_filename: str
        :param methods: List of watermarking instances to use
        :type methods: list[Watermarker]
        :param message: Message to encode
        :type message: str
        :raises WatermarkError: If no watermarking methods are provided
        """
        self._src_filename = src_filename
        self._methods = methods
        self._message: str = message

        self.capacities: Dict[str, int] = {}

        for watermarker in self.__methods:
            name = watermarker.__class__.__name__
            bits = watermarker.get_nbits(self.__src_filename)
            if bits <= 0:
                logger.warning(f"{name}: zero capacity, skipping")
                continue
            self.capacities[name] = bits
        if not self.capacities:
            raise WatermarkError("No watermarking method available with capacity")
        self.max_capacity = max(self.capacities.values())

    def can_encode(self, method_name: Optional[str] = None) -> bool:
        """
        Check if the message can fit in the available capacity. By default, the
        maximum capacity of all watermarking methods is checked.

        :param method_name: Optional name of specific method to check
        :type method_name: Optional[str]
        :return: True if the message can be encoded, False otherwise
        """
        message_bits = len(self._message.encode("utf-8")) * 8

        if method_name is not None:
            return self.capacities.get(method_name, 0) >= message_bits

        if not self.capacities:
            return False

        return self.max_capacity >= message_bits

    def encode(self) -> bytes:
        """
        Encode the message into the binary using watermarking methods.

        Each watermarker in the list is applied in sequence. The last successful
        result is returned.

        :return: Modified binary data containing the encoded message
        :raises WatermarkError: If there is not enough capacity to encode or all methods fail
        """
        if not self.can_encode():
            bits_needed = len(self.__message.encode("utf-8")) * 8
            raise WatermarkError(
                f"Insufficient capacity: {self.max_capacity} bits available, but {bits_needed} needed"
            )

        for wm in self.__methods:
            name = wm.__class__.__name__
            try:
                data = wm.encode(self.__src_filename, self.__message)
                logger.info(f"Encoded with {name}")
                return data
            except WatermarkError as e:
                logger.warning(f"{name} failed: {e}")
            except Exception:
                logger.exception(f"Unexpected error in {name}")

        raise WatermarkError("Failed to encode with any watermarking method")
