import hashlib
import hmac
import json
import unittest
from datetime import datetime, timezone
from unittest import mock

from vuln_intel import config, inventory_integration, scan_store


class InventoryIntegrationTests(unittest.TestCase):
    def test_callback_url_requires_an_exact_allowlisted_host(self):
        with mock.patch.object(config, "INVENTORY_CALLBACK_HOSTS", ["inventory.local"]):
            self.assertEqual(
                inventory_integration._validate_callback_url("http://inventory.local:8080/hooks"),
                "http://inventory.local:8080/hooks",
            )
            with self.assertRaisesRegex(ValueError, "host in VULN_INVENTORY_CALLBACK_HOSTS"):
                inventory_integration._validate_callback_url("http://inventory.local.evil/hooks")
            with self.assertRaises(ValueError):
                inventory_integration._validate_callback_url("http://user:pass@inventory.local/hooks")

    def test_wildcard_addresses_are_rejected_for_public_urls(self):
        with mock.patch.object(config, "REPOSITORY_HOSTS", ["0.0.0.0"]), self.assertRaises(ValueError):
            inventory_integration.repository_connections.validate_repository_url("http://0.0.0.0/team/service")
        with mock.patch.object(config, "PUBLIC_API_BASE_URL", "http://0.0.0.0:8000"), self.assertRaisesRegex(
            inventory_integration.IntegrationConfigurationError,
            "wildcard address",
        ):
            inventory_integration._validate_base_url()

    def test_expired_scan_lease_failure_includes_status_in_callback(self):
        conn = mock.MagicMock()
        cursor = mock.MagicMock()
        conn.cursor.return_value.__enter__.return_value = cursor
        cursor.fetchall.return_value = [(
            "failed", "run-1", "inventory:abc", "a" * 40, "main", None, None, None,
            0, 0, 0, "lease expired",
        )]
        cursor.fetchone.return_value = None

        with mock.patch.object(scan_store, "_connect", return_value=(conn, object())), \
                mock.patch.object(scan_store, "_ensure_schema"), \
                mock.patch.object(inventory_integration, "enqueue_scan_callback") as enqueue:
            self.assertIsNone(scan_store.claim_scan())

        callback_scan = enqueue.call_args.args[2]
        self.assertEqual(callback_scan["status"], "failed")
        self.assertEqual(callback_scan["error"], "lease expired")

    def test_callback_outbox_payload_is_summary_only_and_json_serializable(self):
        cursor = mock.MagicMock()
        cursor.fetchone.return_value = ("asset-42", "http://inventory.local/hooks", b"encrypted")
        scan = {
            "run_id": "scan-1",
            "application_id": "inventory:abc",
            "commit_sha": "a" * 40,
            "ref": "main",
            "status": "succeeded",
            "requested_at": datetime(2026, 11, 18, tzinfo=timezone.utc),
            "started_at": None,
            "completed_at": datetime(2026, 11, 18, 0, 1, tzinfo=timezone.utc),
            "component_count": 8,
            "finding_count": 1,
            "unevaluated_count": 0,
        }
        finding = {"vulnerability_id": "CVE-2025-0001", "package_name": "demo", "severity": "HIGH"}

        inventory_integration.enqueue_scan_callback(cursor, lambda value: value, scan, "scan.completed", [finding])

        insert = cursor.execute.call_args_list[-1]
        payload = insert.args[1][-1]
        self.assertEqual(payload["external_inventory_id"], "asset-42")
        self.assertEqual(payload["scan"]["requested_at"], "2026-11-18T00:00:00+00:00")
        self.assertEqual(payload["scan"]["findings"], [finding])
        json.dumps(payload)

    def test_registration_persists_secrets_encrypted_and_returns_pipeline_details(self):
        conn = mock.MagicMock()
        cursor = mock.MagicMock()
        conn.cursor.return_value.__enter__.return_value = cursor
        cursor.fetchone.return_value = None
        payload = {
            "external_inventory_id": "asset-42",
            "repository_url": "http://gitlab.internal:8080/team/service.git",
            "callback_url": "http://inventory.local/hooks",
            "name": "Payments API",
        }

        with mock.patch.object(config, "REPOSITORY_HOSTS", ["gitlab.internal"]), \
                mock.patch.object(config, "INVENTORY_CALLBACK_HOSTS", ["inventory.local"]), \
                mock.patch.object(config, "PUBLIC_API_BASE_URL", "http://vuln-intel.local:8000"), \
                mock.patch.object(inventory_integration.repository_connections, "_encrypt_secret",
                                  side_effect=lambda value: hashlib.sha256(value.encode()).digest()), \
                mock.patch.object(inventory_integration.database, "_connect", return_value=(conn, object())), \
                mock.patch.object(inventory_integration.database, "_ensure_schema"):
            result = inventory_integration.register_repository(payload)

        self.assertEqual(result["repository"]["external_inventory_id"], "asset-42")
        self.assertEqual(result["repository"]["name"], "Payments API")
        self.assertEqual(
            result["trigger_url"],
            f"http://vuln-intel.local:8000/api/v1/inventory/repositories/{result['repository']['application_id']}/scans",
        )
        self.assertTrue(result["ci_token"].startswith("vint_ci_"))
        self.assertTrue(result["callback_secret"].startswith("vint_cb_"))
        insert_calls = [call for call in cursor.execute.call_args_list if "INSERT INTO inventory_integrations" in call.args[0]]
        self.assertEqual(len(insert_calls), 1)
        self.assertNotIn(result["ci_token"], str(insert_calls[0].args[1]))
        self.assertNotIn(result["callback_secret"], str(insert_calls[0].args[1]))

    def test_ci_token_authentication_compares_a_stored_digest(self):
        conn = mock.MagicMock()
        cursor = mock.MagicMock()
        conn.cursor.return_value.__enter__.return_value = cursor
        token = "vint_ci_example"
        cursor.fetchone.return_value = (hashlib.sha256(token.encode()).digest(),)
        with mock.patch.object(inventory_integration.database, "_connect", return_value=(conn, object())), \
                mock.patch.object(inventory_integration.database, "_ensure_schema"):
            self.assertTrue(inventory_integration.authenticate_ci_credential("inventory:abc", token))
            self.assertFalse(inventory_integration.authenticate_ci_credential("inventory:abc", "wrong"))

    def test_callback_is_signed_over_exact_body_and_redirects_are_not_followed(self):
        callback_payload = {"event_id": "event-1", "event_type": "scan.completed"}
        callback = {
            "event_id": "event-1",
            "callback_url": "http://inventory.local/hooks",
            "encrypted_signing_secret": b"encrypted",
            "payload": callback_payload,
            "attempts": 1,
        }
        response = mock.MagicMock()
        response.status = 202
        response.read.return_value = b""
        response.__enter__.return_value = response
        opener = mock.MagicMock()
        opener.open.return_value = response

        with mock.patch.object(inventory_integration, "claim_callback", return_value=callback), \
                mock.patch.object(inventory_integration, "_validate_callback_url"), \
                mock.patch.object(inventory_integration.repository_connections, "_decrypt_secret", return_value="signing-key"), \
                mock.patch.object(inventory_integration.urllib.request, "build_opener", return_value=opener), \
                mock.patch.object(inventory_integration, "finish_callback") as finish:
            self.assertTrue(inventory_integration.deliver_callback_once())

        request = opener.open.call_args.args[0]
        expected_body = json.dumps(callback_payload, ensure_ascii=False, separators=(",", ":"), default=str).encode()
        expected_signature = hmac.new(b"signing-key", expected_body, hashlib.sha256).hexdigest()
        self.assertEqual(request.data, expected_body)
        self.assertEqual(request.get_header("X-vuln-signature"), f"sha256={expected_signature}")
        self.assertEqual(request.get_header("X-vuln-event-id"), "event-1")
        self.assertIsInstance(opener.open.call_args.kwargs["timeout"], int)
        finish.assert_called_once_with("event-1")


if __name__ == "__main__":
    unittest.main()
