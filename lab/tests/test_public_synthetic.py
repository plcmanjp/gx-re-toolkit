"""New synthetic boundary examples; no project/export authority inputs."""
import unittest
from gx_re_lab.table_delta import table_delta
from gx_re_lab.reducer import Observation, reduce_recipe

class PublicSyntheticTests(unittest.TestCase):
    def test_table_preserves_spacing_and_order(self):
        before = [["0", "LD", "X0", "", "", "", "note"]]
        after = [["0", "LD", "X0 ", "", "", "", "note"], [""] * 7]
        self.assertEqual(table_delta(before, after), {"before_count": 1, "after_count": 2,
                         "changed_cells": [[0, 2]], "added_rows": [1], "removed_rows": []})

    def test_table_rejects_shape_and_nontext(self):
        for invalid in ([[]], [[0] * 7], (), [[""] * 8]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                table_delta(invalid, [])

    def test_reducer_rejects_invalid_budget_before_oracle(self):
        def forbidden(_):
            self.fail("oracle must not be invoked")
        for budget in (0, 1, True, 100001):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                reduce_recipe(["a"], forbidden, budget=budget)

    def test_reducer_rejects_forged_checkpoint(self):
        with self.assertRaises(ValueError):
            reduce_recipe(["a"], lambda _: Observation(True, "x", "0"), checkpoint={})

if __name__ == "__main__":
    unittest.main()
