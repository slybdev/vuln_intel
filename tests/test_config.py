import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vuln_intel import config


class DotenvTests(unittest.TestCase):
    def test_loads_values_and_preserves_process_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "# local settings\nVULN_INTEL_TEST_KEY=fernet==\nVULN_INTEL_TEST_OVERRIDE=file-value\n",
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"VULN_INTEL_TEST_OVERRIDE": "process-value"}):
                config._load_dotenv(path)
                self.assertEqual(os.environ["VULN_INTEL_TEST_KEY"], "fernet==")
                self.assertEqual(os.environ["VULN_INTEL_TEST_OVERRIDE"], "process-value")

    def test_rejects_malformed_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("invalid-entry\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "valid NAME=VALUE"):
                config._load_dotenv(path)


if __name__ == "__main__":
    unittest.main()
