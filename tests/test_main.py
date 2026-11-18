import contextlib
import io
import tempfile
import unittest
from unittest import mock

import main as entry
from tests.test_pipeline_e2e import FakeInternet
from vuln_intel import config
from vuln_intel.utils import read_json


class MainEntryPointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        old = config.DATA_DIR, config.OSV_ECOSYSTEMS
        config.set_data_dir(self.tmp.name)
        config.OSV_ECOSYSTEMS = ["Maven", "PyPI"]
        self.addCleanup(lambda: (config.set_data_dir(old[0]), setattr(config, "OSV_ECOSYSTEMS", old[1])))

    def run_main(self, argv, net):
        out = io.StringIO()
        with mock.patch("vuln_intel.http_client.http_get", net), mock.patch("vuln_intel.collectors.nvd.time.sleep"), \
                contextlib.redirect_stdout(out):
            code = entry.main(argv)
        return code, out.getvalue()

    def test_single_command_pulls_cleans_stores_and_reports(self):
        code, out = self.run_main([], FakeInternet())
        self.assertEqual(code, 0)
        self.assertIn("RESULT: success", out)
        self.assertIn("VULNERABILITY INTELLIGENCE REPORT", out)
        self.assertIn("CVE-2021-44228", out)
        db = read_json(config.DB_PATH, None)["vulnerabilities"]
        self.assertIn("CVE-2021-44228", db)
        self.assertTrue(any((config.DATA_DIR / "raw").glob("*/nvd.json")))

    def test_reports_errors_with_nonzero_exit(self):
        net = FakeInternet()
        net.fail_osv_ecosystem = "Maven"
        code, out = self.run_main([], net)
        self.assertEqual(code, 1)
        self.assertIn("finished WITH ERRORS", out)

    def test_flags_are_passed_through(self):
        code, _ = self.run_main(["--sources", "kev"], FakeInternet())
        self.assertEqual(code, 0)
        self.assertEqual(list(read_json(config.DB_PATH, None)["vulnerabilities"]), ["CVE-2021-44228", "CVE-2023-0001"])


if __name__ == "__main__":
    unittest.main()
