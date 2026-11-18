import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

from vuln_intel import dashboard_data
from vuln_intel.dashboard import application


class DashboardApiTests(unittest.TestCase):
    def request(self, path, query="", method="GET"):
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        body = b"".join(application({
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "REQUEST_METHOD": method,
            "REMOTE_ADDR": "127.0.0.1",
        }, start_response))
        captured["body"] = body
        return captured

    @mock.patch("vuln_intel.dashboard.dashboard_data.get_summary")
    def test_summary_endpoint_returns_json(self, get_summary):
        get_summary.return_value = {"total": 12, "kev": 3}
        response = self.request("/api/summary")
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(json.loads(response["body"]), {"total": 12, "kev": 3})
        self.assertEqual(response["headers"]["Cache-Control"], "no-store")

    @mock.patch("vuln_intel.dashboard.dashboard_data.get_publication_trends")
    def test_publication_trends_endpoint_returns_chart_data(self, get_publication_trends):
        expected = {"months": ["2026-01"], "series": [{"name": "CRITICAL", "values": [3]}]}
        get_publication_trends.return_value = expected
        response = self.request("/api/trends")
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(json.loads(response["body"]), expected)

    @mock.patch("vuln_intel.dashboard_data._read")
    def test_publication_trends_build_ordered_severity_series(self, read):
        read.return_value = [
            ("2026-01", "HIGH", 8),
            ("2026-01", "CRITICAL", 3),
            ("2026-02", "HIGH", 2),
        ]
        result = dashboard_data.get_publication_trends()
        self.assertEqual(result["months"], ["2026-01", "2026-02"])
        self.assertEqual(result["series"][0], {"name": "CRITICAL", "values": [3, 0]})
        self.assertEqual(result["series"][1], {"name": "HIGH", "values": [8, 2]})

    @mock.patch("vuln_intel.dashboard.dashboard_data.list_vulnerabilities")
    def test_vulnerability_list_passes_validated_filters(self, list_vulnerabilities):
        list_vulnerabilities.return_value = {"items": [], "total": 0, "page": 2, "page_size": 10}
        response = self.request("/api/vulnerabilities", urlencode({
            "q": "CVE-2024",
            "severity": "high",
            "exploited": "true",
            "page": "2",
            "page_size": "10",
        }))
        self.assertEqual(response["status"], "200 OK")
        list_vulnerabilities.assert_called_once_with("CVE-2024", "HIGH", True, 2, 10)

    def test_invalid_page_and_filter_are_rejected(self):
        self.assertEqual(self.request("/api/vulnerabilities", "page=abc")["status"], "400 Bad Request")
        self.assertEqual(self.request("/api/vulnerabilities", "severity=URGENT")["status"], "400 Bad Request")

    @mock.patch("vuln_intel.dashboard.dashboard_data.get_vulnerability")
    def test_detail_endpoint_decodes_alias_and_returns_not_found(self, get_vulnerability):
        get_vulnerability.return_value = None
        response = self.request("/api/vulnerabilities/GHSA-abcd-efgh-1234")
        self.assertEqual(response["status"], "404 Not Found")
        get_vulnerability.assert_called_once_with("GHSA-abcd-efgh-1234")

    def test_frontend_is_served_and_other_methods_are_rejected(self):
        page = self.request("/")
        stylesheet = self.request("/styles.css")
        script = self.request("/app.js")
        self.assertEqual(page["status"], "200 OK")
        self.assertEqual(stylesheet["status"], "200 OK")
        self.assertIn(b"Security overview", page["body"])
        self.assertIn(b'theme-color" content="#ffffff"', page["body"])
        self.assertIn(b'id="overview-view"', page["body"])
        self.assertIn(b'id="vulnerabilities-view" hidden', page["body"])
        self.assertIn(b'id="application-scans-view" hidden', page["body"])
        self.assertIn(b'id="scan-github-form"', page["body"])
        self.assertIn(b'id="scan-github-url"', page["body"])
        self.assertIn(b"/api/repositories/scan", script["body"])
        self.assertIn(b'id="scan-app-select"', page["body"])
        self.assertIn(b'id="scan-trend-chart"', page["body"])
        self.assertIn(b'id="scan-severity-chart"', page["body"])
        self.assertIn(b'id="application-finding-rows"', page["body"])
        self.assertIn(b'id="scan-finding-dialog"', page["body"])
        self.assertLess(page["body"].index(b'id="application-finding-rows"'), page["body"].index(b'id="scan-trend-chart"'))
        self.assertIn(b"scan-chart-baseline", script["body"])
        self.assertIn(b"scan-package-legend", script["body"])
        self.assertIn(b'data-view="scans"', page["body"])
        self.assertIn(b'id="repository-settings-view" hidden', page["body"])
        self.assertIn(b'data-view="repositories"', page["body"])
        self.assertIn(b'id="provider-credentials-form"', page["body"])
        self.assertIn(b'id="repository-form"', page["body"])
        self.assertIn(b"Scan now", script["body"])
        self.assertIn(b'<body class="sidebar-collapsed">', page["body"])
        self.assertIn(b'id="sidebar-toggle"', page["body"])
        self.assertNotIn(b"pointerenter", script["body"])
        self.assertNotIn(b"pointerleave", script["body"])
        self.assertNotIn(b'class="topbar"', page["body"])
        self.assertIn(b'class="panel publication-panel"', page["body"])
        self.assertNotIn(b"publication-glass-filter", page["body"])
        self.assertNotIn(b"backdrop-filter", stylesheet["body"])
        self.assertIn(b"--accent: #c1121f", stylesheet["body"])
        self.assertIn(b"position: fixed; inset: auto 0 0", stylesheet["body"])
        self.assertEqual(self.request("/api/summary", method="POST")["status"], "405 Method Not Allowed")

    def test_pipeline_status_omits_large_kev_snapshot(self):
        state = {"sources": {"kev": {
            "watermark": "2026-11-12T00:00:00Z",
            "last_success": "2026-11-12T00:01:00Z",
            "snapshot": {"CVE-2025-0001": "hash"},
        }}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(state), encoding="utf-8")
            with mock.patch.object(dashboard_data.config, "STATE_PATH", path):
                self.assertEqual(dashboard_data.get_pipeline_status(), {
                    "kev": {
                        "watermark": "2026-11-12T00:00:00Z",
                        "last_success": "2026-11-12T00:01:00Z",
                    },
                })


if __name__ == "__main__":
    unittest.main()
