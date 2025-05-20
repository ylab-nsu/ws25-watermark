from typing import Optional
from watermark_framework.io.section_handler import TextSectionHandler, TextSection
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

    def encode(self, message: str, strategy: Optional[Watermarker] = None, dst: Optional[str] = None) -> str:
        if strategy:
            self._validate_strategy(strategy)
        else:
            if not self._strategy:
                raise ValueError("No strategy provided or set as default")
            strategy = self._strategy

        new_text = strategy.encode(self._section, message)
        out = dst or (self._section.src_path + ".patched")
        TextSectionHandler.write(self._section, out, new_text)
        return out

    def decode(self, strategy: Optional[Watermarker] = None) -> str:
        if strategy:
            self._validate_strategy(strategy)
        else:
            if not self._strategy:
                raise ValueError("No strategy provided or set as default")
            strategy = self._strategy

        return strategy.decode(self._section)