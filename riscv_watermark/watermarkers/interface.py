from abc import ABC,abstractmethod

class Watermarker(ABC):

    """
    Encodes specific message using selected method
    """
    @abstractmethod
    def encode(self,src_filename,message):
        pass

    """
    Gets message using selected method
    """
    @abstractmethod
    def decode(self,src_filename):
        pass



    """
    Returns amount of bits available to encode using selected method
    """
    @abstractmethod
    def get_nbits(self,src_filename):
        pass


