class WatermarkError(Exception):
    """Base exception for all watermarking errors."""

    def __init__(self, message="An error occurred in the watermarking process"):
        self.message = message
        super().__init__(self.message)


class EncodingError(WatermarkError):
    """Raised when the encoding process fails."""

    def __init__(self, message="Failed to encode the message"):
        super().__init__(message)


class DecodingError(WatermarkError):
    """Raised when the decoding process fails."""

    def __init__(self, message="Failed to decode the message"):
        super().__init__(message)


class InsufficientCapacityError(WatermarkError):
    """Raised when there's not enough capacity to encode the full message."""

    def __init__(self, bits_available=0, bits_needed=0):
        self.bits_available = bits_available
        self.bits_needed = bits_needed
        message = f"Insufficient capacity: {bits_available} bits available, but {bits_needed} bits needed"
        super().__init__(message)
