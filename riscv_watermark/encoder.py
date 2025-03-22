import logging
import sys

from riscv_watermark.watermarkers.interface import Watermarker

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
        """
        self.__src_filename = src_filename
        self.__methods = methods
        self.__message: str = message
        
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
        #        if not self.can_encode():
        #            logger.info('Not enough size to encode')
        #            raise NoSizeException('')
        new_data = b""
        for watermarker in self.__methods:
            number = watermarker.get_nbits(self.__src_filename)
            number //= 8
            c = list(self.__message)
            msg_len = len(c)
            if number < 1:
                logger.info("low amount of codeable bits")
            if number < msg_len:
                logger.info("Not enough bits to encode the whole message")
            if number > msg_len:
                for i in range(number - msg_len):
                    c.append(" ")  # пока так
            new_data = watermarker.encode(self.__src_filename, c)
        if new_data != b"":
            return new_data
        else:
            logger.info("encoding failed")
            sys.exit()