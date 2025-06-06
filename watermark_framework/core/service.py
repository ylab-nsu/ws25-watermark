from watermark_framework.io import TextSection, TextSectionHandler
from watermark_framework.watermarkers.interface import Watermarker


class WatermarkService:
    """
    Manages watermarking operations on ELF file .text sections.

    Provides methods to encode and decode watermark messages in the .text section
    of an ELF file using a specified watermarking strategy. Supports dynamic strategy
    selection and file switching, with validation for architecture compatibility
    (e.g., X86, RISCV, ARM64, ...).
    """

    def __init__(self, path: str, strategy: Watermarker | None = None):
        """
        Initializes the WatermarkService with an ELF file and optional strategy.

        Loads the .text section from the specified ELF file and sets an optional
        watermarking strategy.

        Args:
            path: Path to the ELF file to load.
            strategy: Optional Watermarker strategy to use for encoding/decoding.

        Raises:
            FileNotFoundError: If the ELF file cannot be opened.
            ValueError: If the .text section is missing, the architecture is unsupported,
                or the strategy does not support the file's architecture.
        """
        self._section: TextSection = TextSectionHandler.load(path)
        self._strategy: Watermarker | None = None
        if strategy:
            self.set_strategy(strategy)

    def _validate_strategy(self, strategy: Watermarker) -> None:
        """
        Validates that a watermarking strategy supports the current architecture.
        """
        if self._section.arch not in strategy.SUPPORTED_ARCHS:
            raise ValueError(f"Strategy {strategy.METHOD_NAME} does not support architecture {self._section.arch}")

    def _get_valid_strategy(self, strategy: Watermarker | None = None) -> Watermarker:
        """
        Selects a valid watermarking strategy, prioritizing the provided one.

        Returns the provided strategy if valid, otherwise falls back to the default
        strategy set for the service.
        """
        if strategy:
            self._validate_strategy(strategy)
            return strategy
        if not self._strategy:
            raise ValueError("No strategy provided or set as default")
        return self._strategy

    def set_strategy(self, strategy: Watermarker) -> None:
        """
        Sets the default watermarking strategy for the service.
        """
        self._validate_strategy(strategy)
        self._strategy = strategy

    def set_file(self, path: str) -> None:
        """
        Loads a new ELF file and updates the .text section.

        Validates that the current strategy (if set) supports the new file's architecture.

        Args:
            path: Path to the new ELF file to load.
        """
        new_section = TextSectionHandler.load(path)
        if self._strategy and new_section.arch not in self._strategy.SUPPORTED_ARCHS:
            raise ValueError(
                f"Current strategy {self._strategy.METHOD_NAME} does not support architecture {new_section.arch}"
            )
        self._section = new_section

    def get_capacity(self, strategy: Watermarker | None = None) -> int:
        """
        Calculates the watermarking capacity of the .text section.

        Determines the number of bits that can be encoded in the .text section
        using the specified or default strategy.

        Args:
            strategy: Optional Watermarker strategy to use for capacity calculation.

        Returns:
            int: The number of bits that can be encoded.
        """
        selected_strategy = self._get_valid_strategy(strategy)
        return selected_strategy.get_nbits(self._section)

    def encode(self, message: bytes, strategy: Watermarker | None = None, dst: str | None = None) -> str:
        """
        Encodes a watermark message into the .text section and writes the result.

        Applies the specified or default watermarking strategy to encode the message
        into the .text section, then writes the modified ELF file to the destination path.

        Args:
            message: The message to encode as bytes.
            strategy: Optional Watermarker strategy to use for encoding.
            dst: Optional destination path for the modified ELF file. Defaults to
                the source path with '.patched' appended.

        Returns:
            str: The path to the modified ELF file.
        """
        selected_strategy = self._get_valid_strategy(strategy)

        message_bits = len(message) * 8
        capacity = selected_strategy.get_nbits(self._section)

        if message_bits > capacity:
            raise ValueError(f"Message size ({message_bits} bits) exceeds section capacity ({capacity} bits)")

        new_text = selected_strategy.encode(self._section, message)
        out = dst or (self._section.src_path + ".patched")
        TextSectionHandler.write(self._section, out, new_text)
        return out

    def decode(self, strategy: Watermarker | None = None) -> bytes:
        """
        Decodes a watermark message from the .text section.

        Uses the specified or default watermarking strategy to extract and return
        the encoded message from the .text section.

        Args:
            strategy: Optional Watermarker strategy to use for decoding.

        Returns:
            bytes: The decoded watermark message.
        """
        selected_strategy = self._get_valid_strategy(strategy)
        return selected_strategy.decode(self._section)
