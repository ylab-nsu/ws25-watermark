class WatermarkError(Exception):
    """Base exception for all watermarking errors."""

    def __init__(self, message="An error occurred in the watermarking process"):
        self.message = message
        super().__init__(self.message)


class NoSizeException(WatermarkError):
    """Raised when there's insufficient space to encode."""

    def __init__(self, message="Not enough space to encode the message"):
        super().__init__(message)


class EncodingError(WatermarkError):
    """Raised when the encoding process fails."""

    def __init__(self, message="Failed to encode the message"):
        super().__init__(message)


class NoMethodsError(WatermarkError):
    """Raised when no watermarking methods are provided."""

    def __init__(self, message="No watermarking methods specified"):
        super().__init__(message)


class InsufficientCapacityError(WatermarkError):
    """Raised when there's not enough capacity to encode the full message."""

    def __init__(self, bits_available=0, bits_needed=0):
        self.bits_available = bits_available
        self.bits_needed = bits_needed
        message = f"Insufficient capacity: {bits_available} bits available, but {bits_needed} bits needed"
        super().__init__(message)
