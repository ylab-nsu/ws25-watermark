from abc import ABC,abstractmethod

class Watermarker(ABC):
    """
    Encodes specific message using selected method
    """
    @abstractmethod
    def encode(self, text_data:bytes, message):
        pass

    """
    Gets message using selected method
    """
    @abstractmethod
    def decode(self, text_data):
        pass

    """
    Returns amount of bits available to encode using selected method
    """
    @abstractmethod
    def get_nbits(self, text_data):
        pass


