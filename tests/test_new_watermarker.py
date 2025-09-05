import unittest

from watermark_framework.watermarkers import (
    get_available_strategies,
    get_strategy,
    get_watermarkers,
)


class TestWatermarkerDiscovery(unittest.TestCase):
    def test_get_available_strategies(self):
        strategies = get_available_strategies()
        self.assertIn("EQ_INSTR", strategies)
        self.assertIn("EQ_INSTR_X86", strategies)

    def test_get_strategy(self):
        strategy = get_strategy("EQ_INSTR")
        self.assertEqual(strategy.METHOD_NAME, "EQ_INSTR")

        strategy = get_strategy("EQ_INSTR_X86")
        self.assertEqual(strategy.METHOD_NAME, "EQ_INSTR_X86")

    def test_get_watermarkers(self):
        watermarkers = get_watermarkers()
        self.assertIn("EQ_INSTR", watermarkers)
        self.assertIn("EQ_INSTR_X86", watermarkers)


if __name__ == "__main__":
    unittest.main()
