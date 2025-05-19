class WatermarkError(Exception):
    """Base exception for all watermarking errors."""

    def _init_(self, message="An error occurred in the watermarking process"):
        self.message = message
        super()._init_(self.message)


class EncodingError(WatermarkError):
    """Raised when the encoding process fails."""

    def _init_(self, message="Failed to encode the message"):
        super()._init_(message)


class DecodingError(WatermarkError):
    """Raised when the decoding process fails."""

    def _init_(self, message="Failed to decode the message"):
        super()._init_(message)


class InsufficientCapacityError(WatermarkError):
    """Raised when there's not enough capacity to encode the full message."""

    def _init_(self, bits_available=0, bits_needed=0):
        self.bits_available = bits_available
        self.bits_needed = bits_needed
        message = f"Insufficient capacity: {bits_available} bits available, but {bits_needed} bits needed"
        super()._init_(message)
