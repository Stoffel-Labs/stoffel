import os
import unittest
from unittest.mock import patch
from all_examples import schedule_waves


class WaveSchedulingTests(unittest.TestCase):
    def test_balances_heavy_examples_without_omitting_or_duplicating_work(self):
        cases = [{"name": f"aes-{i}", "preprocessing_work": 1000} for i in range(11)]
        cases += [{"name": f"small-{i}", "preprocessing_work": 1} for i in range(179)]
        with patch.dict(os.environ, {"STOFFEL_ALL_EXAMPLES_SOURCE_ORDER": "0"}):
            waves = schedule_waves(cases, 16)
        self.assertEqual(len(waves), 12)
        self.assertTrue(all(1 <= len(wave) <= 16 for wave in waves))
        self.assertCountEqual([x["name"] for wave in waves for x in wave], [x["name"] for x in cases])
        self.assertTrue(all(sum(x["preprocessing_work"] == 1000 for x in wave) <= 1 for wave in waves))

    def test_source_order_stress_mode_preserves_original_order(self):
        cases = [{"name": str(i), "preprocessing_work": i} for i in range(20)]
        with patch.dict(os.environ, {"STOFFEL_ALL_EXAMPLES_SOURCE_ORDER": "1"}):
            waves = schedule_waves(cases, 16)
        self.assertEqual(waves, [cases[:16], cases[16:]])

    def test_empty_catalog_and_invalid_capacity(self):
        self.assertEqual(schedule_waves([], 16), [])
        with self.assertRaises(ValueError):
            schedule_waves([], 0)


if __name__ == "__main__":
    unittest.main()
