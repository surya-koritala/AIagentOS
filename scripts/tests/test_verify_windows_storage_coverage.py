import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_windows_storage_coverage import MODULES, REQUIRED, inventory, validate


class WindowsStorageInventoryTests(unittest.TestCase):
    def fixture(self):
        unix = set(REQUIRED) | {module + "::tests::fixture" for module in MODULES}
        windows = unix | {f"windows_private_fs::tests::native_{index}" for index in range(10)}
        return unix, windows

    def test_requires_real_nonzero_platform_parity_and_all_proving_names(self):
        unix, windows = self.fixture()
        self.assertEqual(validate(unix, windows), [])
        windows.remove(REQUIRED[0])
        self.assertTrue(validate(unix, windows))
        self.assertTrue(validate(set(), set()))

    def test_rejects_compiled_out_native_acl_tests_and_ignores_benchmark_summary(self):
        unix, windows = self.fixture()
        windows = {name for name in windows if not name.startswith("windows_private_fs")}
        self.assertTrue(validate(unix, windows))
        self.assertEqual(inventory("storage::tests::a: test\n1 test, 0 benchmarks\n"), {"storage::tests::a"})


if __name__ == "__main__":
    unittest.main()
