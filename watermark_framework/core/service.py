from typing import Optional

from watermark_framework.io.section_handler import TextSection, TextSectionHandler
from watermark_framework.watermarkers.interface import Watermarker


class WatermarkService:

    def __init__(self, path: str, strategy: Optional[Watermarker] = None):
        self._section: TextSection = TextSectionHandler.load(path)
        self._strategy: Optional[Watermarker] = None
        if strategy:
            self.set_strategy(strategy)

    def _validate_strategy(self, strategy: Watermarker) -> None:
        if self._section.arch not in strategy.SUPPORTED_ARCHS:
            raise ValueError(
                f"Strategy {strategy.METHOD_NAME} does not support architecture {self._section.arch}"
            )

    def _get_valid_strategy(self, strategy: Optional[Watermarker] = None) -> Watermarker:
        if strategy:
            self._validate_strategy(strategy)
            return strategy
        if not self._strategy:
            raise ValueError("No strategy provided or set as default")
        return self._strategy

    def set_strategy(self, strategy: Watermarker) -> None:
        self._validate_strategy(strategy)
        self._strategy = strategy

    def set_file(self, path: str) -> None:
        new_section = TextSectionHandler.load(path)
        if self._strategy and new_section.arch not in self._strategy.SUPPORTED_ARCHS:
            raise ValueError(
                f"Current strategy {self._strategy.METHOD_NAME} does not support architecture {new_section.arch}"
            )
        self._section = new_section

    def get_capacity(self, strategy: Optional[Watermarker] = None) -> int:
        selected_strategy = self._get_valid_strategy(strategy)
        return selected_strategy.get_nbits(self._section)

    def encode(self, message: bytes, strategy: Optional[Watermarker] = None, dst: Optional[str] = None) -> str:
        selected_strategy = self._get_valid_strategy(strategy)

        message_bits = len(message) * 8
        capacity = selected_strategy.get_nbits(self._section)

        if message_bits > capacity:
            raise ValueError(
                f"Message size ({message_bits} bits) exceeds section capacity ({capacity} bits)"
        )

        new_text = selected_strategy.encode(self._section, message)
        out = dst or (self._section.src_path + ".patched")
        TextSectionHandler.write(self._section, out, new_text)
        return out

    def decode(self, strategy: Optional[Watermarker] = None) -> bytes:
        selected_strategy = self._get_valid_strategy(strategy)
        return selected_strategy.decode(self._section)
