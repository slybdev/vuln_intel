import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

from vuln_intel import dashboard, dashboard_data
from vuln_intel import asset_store
from vuln_intel import event_store
from vuln_intel.dashboard import application


class DashboardApiTests(unittest.TestCase):
    def request(self, path, query="", method="GET", payload=None, remote_addr="127.0.0.1"):
        captured = {}
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        body = b"".join(application({
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "REQUEST_METHOD": method,
            "REMOTE_ADDR": remote_addr,
            "CONTENT_TYPE": "application/json" if payload is not None else "",
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
        }, start_response))
        captured["body"] = body
        return captured

    @mock.patch("vuln_intel.dashboard.asset_store.list_assets")
    def test_asset_list_passes_filters_and_pagination(self, list_assets):
        expected = {"items": [], "total": 42, "page": 2, "page_size": 10}
        list_assets.return_value = expected
        response = self.request(
            "/api/assets",
            urlencode({"q": "router", "type": "network_device", "status": "active", "page": "2", "page_size": "10"}),
        )
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(json.loads(response["body"]), expected)
        list_assets.assert_called_once_with("router", "network_device", "active", 2, 10)

    def test_asset_list_rejects_invalid_filters_and_pagination(self):
        self.assertEqual(self.request("/api/assets", "type=workstation")["status"], "400 Bad Request")
        self.assertEqual(self.request("/api/assets", "page_size=abc")["status"], "400 Bad Request")

    @mock.patch("vuln_intel.dashboard.asset_store.create_asset")
    def test_asset_create_persists_valid_payload(self, create_asset):
        payload = {"asset_type": "endpoint", "name": "Finance laptop", "identifier": "FIN-LT-01"}
        asset = {"asset_id": "asset-id", **payload}
        create_asset.return_value = asset
        response = self.request("/api/assets", method="POST", payload=payload)
        self.assertEqual(response["status"], "201 Created")
        self.assertEqual(json.loads(response["body"]), {"asset": asset})
        create_asset.assert_called_once_with(payload)

    @mock.patch(
        "vuln_intel.dashboard.asset_store.create_asset",
        side_effect=asset_store.AssetConflict("An asset identifier already exists."),
    )
    def test_asset_create_reports_duplicate_identifier(self, create_asset):
        response = self.request(
            "/api/assets",
            method="POST",
            payload={"asset_type": "server", "name": "Core server", "identifier": "core-01"},
        )
        self.assertEqual(response["status"], "409 Conflict")
        self.assertIn("already exists", json.loads(response["body"])["error"])

    @mock.patch("vuln_intel.dashboard.asset_store.list_assets")
    def test_asset_inventory_is_local_only(self, list_assets):
        response = self.request("/api/assets", remote_addr="192.0.2.10")
        self.assertEqual(response["status"], "403 Forbidden")
        list_assets.assert_not_called()

    @mock.patch("vuln_intel.dashboard.feed_schedule.get_schedule")
    def test_feed_schedule_get_returns_persisted_schedule(self, get_schedule):
        expected = {
            "enabled": True,
            "time": "03:30",
            "next_run_at": "2026-11-18T03:30:00+00:00",
            "last_run_at": None,
            "last_run_status": None,
            "last_run_error": None,
            "last_run_summary": {},
        }
        get_schedule.return_value = expected
        response = self.request("/api/feed-schedule")
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(json.loads(response["body"]), {"schedule": expected})

    @mock.patch("vuln_intel.dashboard.feed_schedule.save_schedule")
    def test_feed_schedule_update_persists_daily_utc_time(self, save_schedule):
        expected = {"enabled": True, "time": "03:30", "next_run_at": None}
        save_schedule.return_value = expected
        response = self.request(
            "/api/feed-schedule",
            method="PUT",
            payload={"enabled": True, "time": "03:30"},
        )
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(json.loads(response["body"]), {"schedule": expected})
        save_schedule.assert_called_once_with(True, "03:30")

    @mock.patch("vuln_intel.dashboard.feed_schedule.get_schedule")
    @mock.patch("vuln_intel.dashboard.feed_schedule.save_schedule")
    def test_feed_schedule_is_local_only(self, save_schedule, get_schedule):
        denied_get = self.request("/api/feed-schedule", remote_addr="192.0.2.10")
        denied_update = self.request(
            "/api/feed-schedule",
            method="PUT",
            payload={"enabled": True, "time": "03:30"},
            remote_addr="192.0.2.10",
        )
        self.assertEqual(denied_get["status"], "403 Forbidden")
        self.assertEqual(denied_update["status"], "403 Forbidden")
        get_schedule.assert_not_called()
        save_schedule.assert_not_called()

    @mock.patch(
        "vuln_intel.dashboard.feed_schedule.save_schedule",
        side_effect=ValueError("time must use 24-hour HH:MM format."),
    )
    def test_feed_schedule_rejects_invalid_time(self, save_schedule):
        response = self.request(
            "/api/feed-schedule",
            method="PUT",
            payload={"enabled": True, "time": "24:00"},
        )
        self.assertEqual(response["status"], "400 Bad Request")
        self.assertIn("HH:MM", json.loads(response["body"])["error"])

    @mock.patch("vuln_intel.dashboard.event_store.list_events")
    def test_security_events_list_passes_filters_and_pagination(self, list_events):
        expected = {"items": [], "total": 61, "page": 2, "page_size": 20}
        list_events.return_value = expected
        response = self.request(
            "/api/security-events",
            urlencode({
                "q": "scan failed",
                "severity": "high",
                "category": "scan",
                "page": "2",
                "page_size": "20",
            }),
        )
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(json.loads(response["body"]), expected)
        list_events.assert_called_once_with("scan failed", "HIGH", "scan", 2, 20)

    def test_security_events_reject_invalid_filters_and_are_local_only(self):
        invalid = self.request("/api/security-events", "severity=urgent")
        self.assertEqual(invalid["status"], "400 Bad Request")
        denied = self.request("/api/security-events", remote_addr="192.0.2.10")
        self.assertEqual(denied["status"], "403 Forbidden")

    @mock.patch("vuln_intel.dashboard.event_store.get_event_summary")
    def test_security_event_summary_uses_real_event_counts(self, get_event_summary):
        summary = {"total": 14, "last_24_hours": 3, "high_severity": 2, "failed": 1}
        get_event_summary.return_value = summary
        response = self.request("/api/security-events/summary")
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(json.loads(response["body"]), summary)

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

    @mock.patch("vuln_intel.dashboard.scan_store.get_application_finding_details")
    def test_application_finding_detail_returns_stored_scan_evidence(self, get_finding):
        evidence = {"trivy": [{"Title": "Example advisory", "References": ["https://example.test"]}]}
        finding = {"vulnerability_id": "CVE-2026-1234", "evidence": evidence}
        get_finding.return_value = finding
        query = urlencode({
            "ref": "refs/heads/main",
            "vulnerability_id": "CVE-2026-1234",
            "package_name": "example-package",
            "installed_version": "1.2.3",
        })

        response = self.request(
            "/api/applications/github%3Aacme%3Aapi/finding-details",
            query,
        )

        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(json.loads(response["body"]), finding)
        get_finding.assert_called_once_with(
            "github:acme:api",
            "refs/heads/main",
            "CVE-2026-1234",
            "example-package",
            "1.2.3",
        )

    def test_application_finding_detail_requires_complete_identity(self):
        response = self.request(
            "/api/applications/github%3Aacme%3Aapi/finding-details",
            "ref=main&vulnerability_id=CVE-2026-1234",
        )
        self.assertEqual(response["status"], "400 Bad Request")

    @mock.patch("vuln_intel.dashboard.dashboard_data.get_vulnerability")
    def test_detail_endpoint_decodes_alias_and_returns_not_found(self, get_vulnerability):
        get_vulnerability.return_value = None
        response = self.request("/api/vulnerabilities/GHSA-abcd-efgh-1234")
        self.assertEqual(response["status"], "404 Not Found")
        get_vulnerability.assert_called_once_with("GHSA-abcd-efgh-1234")

    def test_tactical_ops_frontend_is_served_from_build_output(self):
        with tempfile.TemporaryDirectory() as directory:
            frontend_dir = Path(directory)
            (frontend_dir / "assets").mkdir()
            (frontend_dir / "index.html").write_text("<!doctype html><title>Tactical Ops</title>", encoding="utf-8")
            (frontend_dir / "assets" / "app.js").write_text("window.tacticalOps = true;", encoding="utf-8")
            with mock.patch.object(dashboard, "FRONTEND_DIR", frontend_dir):
                page = self.request("/")
                script = self.request("/assets/app.js")
                missing = self.request("/styles.css")

        self.assertEqual(page["status"], "200 OK")
        self.assertIn(b"Tactical Ops", page["body"])
        self.assertEqual(script["status"], "200 OK")
        self.assertIn(b"window.tacticalOps", script["body"])
        self.assertEqual(missing["status"], "404 Not Found")
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
