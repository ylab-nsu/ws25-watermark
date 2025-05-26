class WatermarkError(Exception):
    """Base exception for all watermarking errors."""

    def _init_(self, message="An error occurred in the watermarking process"):
        self.message = message
        super().__init__(self.message)
