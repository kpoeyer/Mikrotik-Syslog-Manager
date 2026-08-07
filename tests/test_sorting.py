import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "Mikrotik-Syslog-Manager.py"
spec = importlib.util.spec_from_file_location("syslog_app", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SortingTests(unittest.TestCase):
    def test_sort_value_coercion_handles_numbers_and_text(self):
        self.assertEqual(module.MikroTikSyslogProApp._coerce_sort_value("10"), (0, 10.0))
        self.assertEqual(module.MikroTikSyslogProApp._coerce_sort_value("2"), (0, 2.0))
        self.assertEqual(module.MikroTikSyslogProApp._coerce_sort_value("abc"), (1, "abc"))
        self.assertEqual(module.MikroTikSyslogProApp._coerce_sort_value(None), (2, ""))

    def test_sort_rows_by_column(self):
        rows = [("b", 2), ("a", 10), ("c", 1)]
        sorted_rows = module.MikroTikSyslogProApp._sort_rows(rows, 0, False)
        self.assertEqual([row[0] for row in sorted_rows], ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
