import logging
import sys

from riscv_watermark.watermarkers.interface import Watermarker
from riscv_watermark.exceptions import NoMethodsError, InsufficientCapacityError, EncodingError, NoSizeException

logger = logging.getLogger(__name__)


class Encoder:
    """
    Handles the encoding of messages into binary files using watermarking techniques.
    
    This class coordinates the watermarking process using one or more watermarking
    methods to encode hidden messages into binary files.
    """
    
    def __init__(self, src_filename: str, methods: list[Watermarker], message: str):
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
        self.__src_filename = src_filename
        self.__methods = methods
        self.__message: str = message
        
        if not self.__methods:
            raise NoMethodsError()
        
        self.available_bits_list = [
            watermarker.get_nbits(self.__src_filename) for watermarker in self.__methods
        ]
        
    def get_nbits(self) -> int:
        """
        Get the total number of bits available for encoding across all methods.
        
        :return: Total number of bits available for encoding
        """
        return sum(self.available_bits_list)

    def can_encode(self) -> bool:
        """
        Check if the message can fit in the available capacity.
        
        :return: True if the message can be encoded, False otherwise
        """
        return self.get_nbits() >= len(self.__message.encode("utf-8")) * 8

    def encode(self) -> bytes:
        """
        Encode the message into the binary using watermarking methods.
        
        Each watermarker in the list is applied in sequence. The last successful
        result is returned.
        
        :return: Modified binary data containing the encoded message
        :raises InsufficientCapacityError: If there is not enough capacity to encode the message
        :raises EncodingError: If all watermarking methods fail
        """
        
        if not self.can_encode():
            msg_bits_needed = len(self.__message.encode("utf-8")) * 8
            raise InsufficientCapacityError(
                bits_available=self.get_nbits(),
                bits_needed=msg_bits_needed
            )
        
        new_data = b""
        
        for watermarker in self.__methods:
            try:
                bits_capacity = watermarker.get_nbits(self.__src_filename)
                bytes_capacity = bits_capacity // 8
                
                message = self.__message
                msg_len = len(message)
                
                if bytes_capacity < 1:
                    logger.warning(
                        f"Skipping {watermarker.__class__.__name__}: "
                        f"Low amount of encodable bits: {bits_capacity}"
                    )
                    continue
                    
                if bytes_capacity < msg_len:
                    logger.warning(
                        f"Message too large for watermarker: {msg_len} bytes needed, "
                        f"but only {bytes_capacity} bytes available"
                    )
                    continue
                else:
                    message += " " * (bytes_capacity - msg_len)
                
                new_data = watermarker.encode(self.__src_filename, message)
                
                if new_data:
                    logger.info(
                        f"Successfully encoded message using "
                        f"{watermarker.__class__.__name__}"
                    )
                    return new_data
            except Exception as e:
                logger.warning(f"{watermarker.__class__.__name__} method failed: {str(e)}")
        
        logger.error("All watermarking methods failed")
        raise EncodingError("Failed to encode message with any available watermarking method")