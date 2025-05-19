import logging
from typing import Dict, Optional

from riscv_watermark.exceptions import EncodingError, InsufficientCapacityError
from riscv_watermark.watermarkers.interface import Watermarker

logger = logging.getLogger(__name__)


class Encoder:
    """
    Handles the encoding of messages into binary files using watermarking techniques.

    This class coordinates the watermarking process using one or more watermarking
    methods to encode hidden messages into binary files.
    """

    def _init_(self, src_filename: str, methods: list[Watermarker], message: str):
        """
        Initialize the encoder with source file, watermarking methods, and message.

        :param src_filename: Path to the source binary file
        :type src_filename: str
        :param methods: List of watermarking instances to use
        :type methods: list[Watermarker]
        :param message: Message to encode
        :type message: str
        :raises NoMethodsError: If no watermarking methods are provided
        """
        self._src_filename = src_filename
        self._methods = methods
        self._message: str = message

        self.capacities: Dict[str, int] = {}
        for watermarker in self._methods:
            method_name = watermarker._class_._name_
            bits = watermarker.get_nbits(self._src_filename)
            self.capacities[method_name] = bits
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
        :raises InsufficientCapacityError: If there is not enough capacity to encode
        :raises EncodingError: If all watermarking methods fail
        """

        if not self.can_encode():
            msg_bits_needed = len(self._message.encode("utf-8")) * 8
            raise InsufficientCapacityError(bits_available=self.max_capacity, bits_needed=msg_bits_needed)

        new_data = b""

        for watermarker in self._methods:
            try:
                bits_capacity = watermarker.get_nbits(self._src_filename)

                message = self._message
                msg_len = len(message)

                if bits_capacity * 8 < 1:
                    logger.warning(
                        f"Skipping {watermarker._class_._name_}: "
                        f"Low amount of encodable bits: {bits_capacity}"
                    )
                    continue

                if bits_capacity < msg_len * 8:
                    logger.warning(
                        f"Message too large for watermarker: {msg_len} bytes needed, "
                        f"but only {bits_capacity * 8} bytes available"
                    )
                    continue
                else:
                    message += " " * (bits_capacity * 8 - msg_len)

                new_data = watermarker.encode(self._src_filename, message)

                if new_data:
                    logger.info(f"Successfully encoded message using {watermarker._class_._name_}")
                    return new_data
            except Exception as e:
                logger.warning(f"{watermarker._class_._name_} method failed: {str(e)}")

        logger.error("All watermarking methods failed")
        raise EncodingError("Failed to encode message with any available watermarking method")
