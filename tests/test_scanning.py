import hashlib
import hmac
import io
import json
import tempfile
import unittest
import urllib.error
import uuid
from pathlib import Path
from unittest import mock

from vuln_intel import config, inventory_integration, repository_connections, scan_store
from vuln_intel.dashboard import application
from vuln_intel.scan_matching import (
    component_matches_affected,
    normalize_component,
    parse_cyclonedx,
    parse_purl,
    parse_trivy_report,
    version_is_affected,
)
from vuln_intel.scan_service import combine_findings, request_latest_scan, validate_scan_request
from vuln_intel.scan_worker import resolve_repository_head


class PackageUrlTests(unittest.TestCase):
    def test_extracts_supported_package_identities(self):
        self.assertEqual(parse_purl("pkg:pypi/Django@4.2.0")["package_name"], "django")
        self.assertEqual(parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")["package_name"],
                         "org.apache.logging.log4j:log4j-core")
        self.assertEqual(parse_purl("pkg:npm/%40angular/core@17.0.0")["package_name"], "@angular/core")

    def test_cyclonedx_and_trivy_reports_produce_components_and_findings(self):
        components = parse_cyclonedx({
            "bomFormat": "CycloneDX",
            "components": [{"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}],
        })
        report_components, findings = parse_trivy_report({
            "SchemaVersion": 2,
            "Results": [{
                "Target": "package-lock.json",
                "Type": "npm",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2021-23337",
                    "PkgName": "lodash",
                    "PkgIdentifier": {"PURL": "pkg:npm/lodash@4.17.20"},
                    "InstalledVersion": "4.17.20",
                    "FixedVersion": "4.17.21",
                    "Severity": "HIGH",
                }],
            }],
        })
        self.assertEqual(components[0]["component_key"], report_components[0]["component_key"])
        self.assertEqual(findings[0]["component_key"], components[0]["component_key"])
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_repository_urls_are_limited_to_allowed_https_hosts(self):
        self.assertEqual(repository_connections.validate_repository_url("https://github.com/acme/service.git"),
                         "https://github.com/acme/service.git")
        self.assertEqual(repository_connections.provider_for_repository("https://github.com/acme/service"), "github")
        self.assertEqual(repository_connections.provider_for_repository("https://gitlab.com/acme/service"), "gitlab")
        for value in ("http://github.com/acme/service", "https://github.com.evil.test/acme/service",
                      "https://user:pass@github.com/acme/service", "https://127.0.0.1/private"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                repository_connections.validate_repository_url(value)
        with self.assertRaises(ValueError):
            repository_connections.provider_for_repository("https://example.com/acme/service")

    def test_self_hosted_gitlab_url_supports_nested_groups(self):
        with mock.patch.object(config, "REPOSITORY_HOSTS", ["gitlab.internal.example"]):
            details = repository_connections.application_from_url(
                "https://gitlab.internal.example/Division/Platform/Service.git"
            )
            self.assertEqual(details["application_id"], "gitlab:gitlab.internal.example:division:platform:service")
            self.assertEqual(details["name"], "Division/Platform/Service")
            self.assertEqual(details["repository_url"], "https://gitlab.internal.example/Division/Platform/Service")
            self.assertEqual(
                repository_connections.provider_for_repository(details["repository_url"]),
                "gitlab",
            )
            with self.assertRaisesRegex(ValueError, "invalid group or project"):
                repository_connections.application_from_url(
                    "https://gitlab.internal.example/Division/%2Fprivate/Service"
                )

    def test_github_repository_url_creates_a_stable_application_identity(self):
        repository = repository_connections.github_application_from_url("https://github.com/Acme/Service.git")
        repeated = repository_connections.github_application_from_url("https://github.com/acme/service")
        self.assertEqual(repository["application_id"], repeated["application_id"])
        self.assertEqual(repository["application_id"], "github:acme:service")
        self.assertEqual(repository["name"], "Acme/Service")
        self.assertEqual(repository["repository_url"], "https://github.com/Acme/Service")
        with self.assertRaisesRegex(ValueError, "repository root URL"):
            repository_connections.github_application_from_url("https://github.com/acme/service/tree/main")
        with self.assertRaisesRegex(ValueError, "GitHub repository URL"):
            repository_connections.github_application_from_url("https://gitlab.com/acme/service")

    def test_provider_username_and_token_are_encrypted_and_key_is_required(self):
        from cryptography.fernet import Fernet

        credential = "github_pat_example_readonly"
        with mock.patch.object(config, "REPOSITORY_ENCRYPTION_KEY", Fernet.generate_key().decode()):
            encrypted_username = repository_connections._encrypt_secret("repository-user")
            encrypted_password = repository_connections._encrypt_secret(credential)
            self.assertNotIn(credential.encode(), encrypted_password)
            self.assertEqual(repository_connections._decrypt_secret(encrypted_username), "repository-user")
            self.assertEqual(repository_connections._decrypt_secret(encrypted_password), credential)
        with (mock.patch.object(config, "REPOSITORY_ENCRYPTION_KEY", ""),
              self.assertRaises(repository_connections.RepositoryEncryptionError)):
            repository_connections._encrypt_secret(credential)

    @mock.patch("vuln_intel.repository_connections.urllib.request.urlopen")
    def test_github_credentials_are_verified_for_the_entered_account(self, urlopen):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"login":"Octocat"}'
        urlopen.return_value = response

        result = repository_connections._verify_github_credentials("octocat", "private-token")

        self.assertEqual(result, {"status": "verified"})
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/user")
        self.assertEqual(request.get_header("Authorization"), "Bearer private-token")
        urlopen.assert_called_once_with(mock.ANY, timeout=10)

    @mock.patch("vuln_intel.repository_connections.urllib.request.urlopen")
    def test_github_credentials_reject_invalid_tokens_and_account_mismatch(self, urlopen):
        invalid_token = urllib.error.HTTPError(
            "https://api.github.com/user", 401, "Unauthorized", {}, io.BytesIO(b""),
        )
        urlopen.side_effect = invalid_token
        with self.assertRaisesRegex(repository_connections.ProviderCredentialVerificationError, "rejected"):
            repository_connections._verify_github_credentials("octocat", "invalid-token")

        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"login":"other-user"}'
        urlopen.side_effect = None
        urlopen.return_value = response
        with self.assertRaisesRegex(repository_connections.ProviderCredentialVerificationError, "not @octocat"):
            repository_connections._verify_github_credentials("octocat", "private-token")

    @mock.patch("vuln_intel.repository_connections._connect")
    @mock.patch("vuln_intel.repository_connections._verify_github_credentials")
    def test_invalid_github_token_is_rejected_before_credentials_are_saved(self, verify, connect):
        from cryptography.fernet import Fernet

        verify.side_effect = repository_connections.ProviderCredentialVerificationError("invalid token")
        with mock.patch.object(config, "REPOSITORY_ENCRYPTION_KEY", Fernet.generate_key().decode()):
            with self.assertRaises(repository_connections.ProviderCredentialVerificationError):
                repository_connections.save_provider_credentials("github", "octocat", "bad-token")
        connect.assert_not_called()
        verify.assert_called_once_with("octocat", "bad-token")

    def test_github_credentials_are_saved_only_after_successful_verification(self):
        from cryptography.fernet import Fernet

        conn = mock.MagicMock()
        cursor = mock.MagicMock()
        conn.cursor.return_value.__enter__.return_value = cursor
        cursor.fetchone.side_effect = [None, ("github", "2026-11-16T00:00:00Z")]
        verification = {"status": "verified"}
        verify = mock.Mock(return_value=verification)

        def connect_after_verification():
            verify.assert_called_once_with("octocat", "private-token")
            return conn, None

        with mock.patch.object(config, "REPOSITORY_ENCRYPTION_KEY", Fernet.generate_key().decode()), \
                mock.patch.object(repository_connections, "_encrypt_secret", return_value=b"encrypted"), \
                mock.patch.object(repository_connections, "_verify_github_credentials", verify), \
                mock.patch.object(repository_connections, "_connect", side_effect=connect_after_verification), \
                mock.patch.object(repository_connections.event_store, "insert_event") as insert_event, \
                mock.patch.object(repository_connections, "_ensure_schema"):
            result = repository_connections.save_provider_credentials("github", "octocat", "private-token")

        self.assertEqual(result["verification"], verification)
        self.assertEqual(cursor.execute.call_count, 2)
        insert_event.assert_called_once()


class InternalVersionMatchingTests(unittest.TestCase):
    def test_semver_and_pep440_bounds_are_inclusive_or_exclusive_as_declared(self):
        semver = {"scheme": "semver", "versions": [], "ranges": [
            {"introduced": "1.0.0", "fixed": "2.0.0"},
        ]}
        pep440 = {"scheme": "pep440", "versions": [], "ranges": [
            {"introduced": "1.0", "last_affected": "1.5"},
        ]}
        self.assertTrue(version_is_affected("1.9.9", semver))
        self.assertFalse(version_is_affected("2.0.0", semver))
        self.assertTrue(version_is_affected("1.5", pep440))
        self.assertFalse(version_is_affected("1.5.1", pep440))

    def test_unsupported_scheme_or_missing_distro_release_is_unevaluated(self):
        self.assertIsNone(version_is_affected("1.0", {"scheme": "maven", "ranges": [{"fixed": "2.0"}]}))
        component = normalize_component({"purl": "pkg:deb/debian/curl@7.88.1?arch=amd64&distro=debian-12"})
        affected = {
            "ecosystem": "Debian",
            "release": "12",
            "package": "curl",
            "scheme": "dpkg",
            "ranges": [{"introduced": "0", "fixed": "7.89.0"}],
        }
        self.assertIsNone(component_matches_affected(component, affected))

    def test_only_exact_package_ecosystem_and_affected_version_match(self):
        component = normalize_component({"purl": "pkg:npm/lodash@4.17.20"})
        affected = {
            "ecosystem": "npm",
            "package": "lodash",
            "scheme": "semver",
            "versions": [],
            "ranges": [{"introduced": "0", "fixed": "4.17.21"}],
        }
        self.assertTrue(component_matches_affected(component, affected))
        self.assertFalse(component_matches_affected(component, {**affected, "package": "other"}))
        self.assertFalse(component_matches_affected(component, {**affected, "ecosystem": "PyPI"}))

    def test_known_cpe_alias_matches_npm_version_ranges(self):
        affected = {
            "ecosystem": "cpe",
            "vendor": "axios",
            "package": "axios",
            "cpe_part": "a",
            "scheme": "generic",
            "ranges": [
                {"introduced": "0", "fixed": "0.31.1"},
                {"introduced": "1.0.0", "fixed": "1.15.1"},
            ],
        }
        vulnerable = normalize_component({"purl": "pkg:npm/axios@1.7.4"})
        fixed = normalize_component({"purl": "pkg:npm/axios@1.18.1"})

        self.assertTrue(component_matches_affected(vulnerable, affected))
        self.assertFalse(component_matches_affected(fixed, affected))

    def test_cpe_package_matching_uses_platform_or_vendor_evidence(self):
        cases = [
            (
                "pkg:npm/follow-redirects@1.16.0",
                {
                    "vendor": "follow-redirects_project",
                    "package": "follow-redirects",
                    "target_sw": "node.js",
                    "ranges": [{"introduced": "0", "fixed": "1.16.0"}],
                },
                False,
            ),
            (
                "pkg:pypi/twisted@26.4.0",
                {
                    "vendor": "twisted",
                    "package": "twisted",
                    "ranges": [
                        {"introduced": "0", "fixed": "26.4.0rc2"},
                        {"introduced": "26.4.0-rc1", "last_affected": "26.4.0-rc1"},
                    ],
                },
                False,
            ),
            (
                "pkg:pypi/twisted@26.4.0rc1",
                {
                    "vendor": "twisted",
                    "package": "twisted",
                    "ranges": [
                        {"introduced": "0", "fixed": "26.4.0rc2"},
                        {"introduced": "26.4.0-rc1", "last_affected": "26.4.0-rc1"},
                    ],
                },
                True,
            ),
            (
                "pkg:pypi/urllib3@2.7.0",
                {
                    "vendor": "python",
                    "package": "urllib3",
                    "ranges": [{"introduced": "1.23", "fixed": "2.7.0"}],
                },
                False,
            ),
            (
                "pkg:npm/fast-uri@3.1.2",
                {
                    "vendor": "fast-uri",
                    "package": "fast-uri",
                    "ranges": [{"introduced": "0", "fixed": "3.1.2"}],
                },
                False,
            ),
        ]
        for purl, cpe_fields, expected in cases:
            with self.subTest(purl=purl, expected=expected):
                component = normalize_component({"purl": purl})
                affected = {
                    "ecosystem": "cpe",
                    "cpe_part": "a",
                    "scheme": "generic",
                    **cpe_fields,
                }
                self.assertIs(component_matches_affected(component, affected), expected)

        conflicting_platform = {
            "ecosystem": "cpe",
            "vendor": "python",
            "package": "follow-redirects",
            "target_sw": "node.js",
            "cpe_part": "a",
            "scheme": "generic",
            "ranges": [{"introduced": "0", "fixed": "2.0.0"}],
        }
        python_package = normalize_component({"purl": "pkg:pypi/follow-redirects@1.0"})
        self.assertFalse(component_matches_affected(python_package, conflicting_platform))

    def test_unmapped_cpe_product_is_unevaluated_not_silently_ignored(self):
        component = normalize_component({"purl": "pkg:npm/axios@1.7.4"})
        affected = {
            "ecosystem": "cpe",
            "vendor": "unknown-vendor",
            "package": "axios",
            "cpe_part": "a",
            "scheme": "generic",
            "ranges": [{"introduced": "1.0.0", "fixed": "1.15.1"}],
        }

        self.assertIsNone(component_matches_affected(component, affected))


class CombinedFindingTests(unittest.TestCase):
    def test_trivy_and_internal_matches_merge_without_losing_source_evidence(self):
        component = normalize_component({"purl": "pkg:npm/lodash@4.17.20"})
        internal = {
            "ids": ["CVE-2021-23337"],
            "title": "Prototype pollution",
            "severity": "CRITICAL",
            "sources": ["osv", "ghsa"],
            "exploitation": {"in_kev": False, "epss": {"score": 0.8}},
            "references": ["https://example.test/advisory"],
            "affected": [{
                "ecosystem": "npm",
                "package": "lodash",
                "scheme": "semver",
                "versions": [],
                "ranges": [{"introduced": "0", "fixed": "4.17.21"}],
                "patched": ["4.17.21"],
            }],
        }
        with mock.patch.object(scan_store, "resolve_identifier", return_value="CVE-2021-23337"):
            with mock.patch.object(
                scan_store, "get_candidate_vulnerabilities", return_value=[("CVE-2021-23337", internal)]
            ):
                findings, unevaluated = combine_findings(
                    [component],
                    [{
                        "component_key": component["component_key"],
                        "vulnerability_id": "CVE-2021-23337",
                        "severity": "HIGH",
                        "fixed_version": "4.17.21",
                        "evidence": {"Title": "Trivy title"},
                    }],
                )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["sources"], ["trivy", "vuln_intel"])
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("trivy", findings[0]["evidence"])
        self.assertIn("vuln_intel", findings[0]["evidence"])
        self.assertEqual(findings[0]["fixed_version"], "4.17.21")
        self.assertEqual(unevaluated, [])

    def test_cpe_advisory_matches_component_without_trivy_finding(self):
        component = normalize_component({"purl": "pkg:npm/axios@1.7.4"})
        internal = {
            "ids": ["CVE-2026-42033"],
            "severity": "HIGH",
            "affected": [{
                "ecosystem": "cpe",
                "vendor": "axios",
                "package": "axios",
                "cpe_part": "a",
                "scheme": "generic",
                "ranges": [
                    {"introduced": "0", "fixed": "0.31.1"},
                    {"introduced": "1.0.0", "fixed": "1.15.1"},
                ],
            }],
        }
        with mock.patch.object(scan_store, "resolve_identifier", return_value="CVE-2026-42033"):
            with mock.patch.object(
                scan_store, "get_candidate_vulnerabilities", return_value=[("CVE-2026-42033", internal)]
            ):
                findings, unevaluated = combine_findings([component], [])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["sources"], ["vuln_intel"])
        self.assertEqual(findings[0]["fixed_version"], "1.15.1")
        self.assertEqual(unevaluated, [])

    def test_uncomparable_internal_ranges_are_reported_not_marked_safe(self):
        component = normalize_component({"purl": "pkg:maven/org.example/widget@1.2.3"})
        internal = {
            "ids": ["CVE-2025-0001"],
            "severity": "HIGH",
            "affected": [{
                "ecosystem": "Maven",
                "package": "org.example:widget",
                "scheme": "maven",
                "ranges": [{"introduced": "1.0", "fixed": "2.0"}],
            }],
        }
        with mock.patch.object(scan_store, "resolve_identifier", return_value=None):
            with mock.patch.object(
                scan_store, "get_candidate_vulnerabilities", return_value=[("CVE-2025-0001", internal)]
            ):
                findings, unevaluated = combine_findings([component], [])
        self.assertEqual(findings, [])
        self.assertEqual(unevaluated[0]["canonical_id"], "CVE-2025-0001")


class FindingDetailsStoreTests(unittest.TestCase):
    def test_application_finding_details_returns_full_evidence_for_exact_package_version(self):
        evidence = {"trivy": [{"Title": "Example advisory"}], "vuln_intel": []}
        row = (
            "refs/heads/main", "CVE-2026-1234", "CVE-2026-1234", "npm", None, "example-package",
            "pkg:npm/example-package@1.2.3", "1.2.3", "1.2.4", "HIGH", "active", None, None,
            ["trivy"], evidence,
        )
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        cursor = mock.MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor
        cursor.fetchone.return_value = row

        with mock.patch.object(scan_store, "_connect", return_value=(connection, None)), \
                mock.patch.object(scan_store, "_ensure_schema"):
            result = scan_store.get_application_finding_details(
                "app-1", "refs/heads/main", "CVE-2026-1234", "example-package", "1.2.3"
            )

        self.assertEqual(result["evidence"], evidence)
        query, parameters = cursor.execute.call_args.args
        self.assertIn("AND installed_version = %s", query)
        self.assertEqual(parameters, (
            "app-1", "refs/heads/main", "CVE-2026-1234", "CVE-2026-1234",
            "example-package", "1.2.3",
        ))

    def test_candidate_query_includes_cpe_product_advisories(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        cursor = mock.MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor
        cursor.fetchall.return_value = []

        with mock.patch.object(scan_store, "_connect", return_value=(connection, None)), \
                mock.patch.object(scan_store, "_ensure_schema"):
            scan_store.get_candidate_vulnerabilities("npm", "axios")

        query, parameters = cursor.execute.call_args.args
        self.assertIn("OR payload->'affected' @>", query)
        self.assertEqual(json.loads(parameters[0]), [{"ecosystem": "npm", "package": "axios"}])
        self.assertEqual(json.loads(parameters[1]), [{"ecosystem": "cpe", "package": "axios"}])

class ScanRequestTests(unittest.TestCase):
    def test_scan_request_requires_full_commit_and_event_id(self):
        payload = {
            "application_id": "app-12",
            "commit_sha": "a" * 40,
            "ref": "refs/heads/main",
            "event_id": "push-123",
            "repository_url": "https://evil.example/ignored",
        }
        normalized = validate_scan_request(payload)
        self.assertEqual(normalized["application_id"], "app-12")
        self.assertNotIn("repository_url", normalized)
        for key, value in (("commit_sha", "abc"), ("event_id", ""), ("application_id", "../etc")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_scan_request({**payload, key: value})

    @mock.patch("vuln_intel.scan_service.scan_store.enqueue_scan")
    def test_manual_scan_queues_latest_commit_target(self, enqueue_scan):
        enqueue_scan.return_value = ({"run_id": "scan-1", "status": "queued"}, True)
        run, created = request_latest_scan("app-12")
        self.assertTrue(created)
        self.assertEqual(run["status"], "queued")
        args = enqueue_scan.call_args.args
        self.assertEqual(args[:3], ("app-12", "HEAD", "HEAD"))
        self.assertEqual(len(args[3]), 64)
        with self.assertRaises(ValueError):
            request_latest_scan("../bad")

    def test_expired_terminal_scan_queues_failed_inventory_callback(self):
        cursor = mock.MagicMock()
        cursor.fetchall.return_value = [
            ("scan-1", "app-1", 3, "a" * 40, "main", 12, 2, 1, None)
        ]
        cursor.fetchone.return_value = None
        connection = mock.MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor
        with (
            mock.patch.object(scan_store, "_connect", return_value=(connection, lambda value: value)),
            mock.patch.object(scan_store, "_ensure_schema"),
            mock.patch.object(scan_store.event_store, "insert_event"),
            mock.patch.object(scan_store.inventory_integration, "enqueue_scan_callback") as enqueue_callback,
        ):
            result = scan_store.claim_scan()

        self.assertIsNone(result)
        payload = enqueue_callback.call_args.args[4]
        self.assertEqual(payload["event"], "scan.failed")
        self.assertEqual(payload["scan_id"], "scan-1")
        self.assertEqual(payload["summary"]["components_scanned"], 12)

    @mock.patch("vuln_intel.scan_worker.subprocess.run")
    def test_worker_resolves_default_branch_head(self, run):
        commit_sha = "a" * 40
        run.return_value = mock.Mock(
            returncode=0,
            stdout=f"ref: refs/heads/main\tHEAD\n{commit_sha}\tHEAD\n",
            stderr="",
        )
        with tempfile.TemporaryDirectory() as directory:
            resolved = resolve_repository_head(
                "https://github.com/acme/service.git", Path(directory)
            )
        self.assertEqual(resolved, (commit_sha, "refs/heads/main"))
        self.assertIn("ls-remote", run.call_args.args[0])

    def request(self, path, method="GET", body=None, headers=None, query=""):
        captured = {}
        data = json.dumps(body).encode("utf-8") if body is not None else b""

        def start_response(status, response_headers):
            captured["status"] = status
            captured["headers"] = dict(response_headers)

        environ = {
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "REQUEST_METHOD": method,
            "REMOTE_ADDR": "127.0.0.1",
            "CONTENT_LENGTH": str(len(data)),
            "CONTENT_TYPE": "application/json" if body is not None else "",
            "wsgi.input": io.BytesIO(data),
        }
        for key, value in (headers or {}).items():
            environ[key] = value
        captured["body"] = b"".join(application(environ, start_response))
        return captured

    @mock.patch("vuln_intel.dashboard.scan_service.request_scan")
    def test_scan_post_requires_bearer_token_and_returns_accepted(self, request_scan):
        request_scan.return_value = ({"run_id": str(uuid.uuid4()), "status": "queued"}, True)
        payload = {"application_id": "app-1", "commit_sha": "b" * 40, "ref": "main", "event_id": "42"}
        with mock.patch.object(config, "SCAN_API_TOKEN", "test-token"):
            denied = self.request("/api/scans", "POST", payload)
            accepted = self.request("/api/scans", "POST", payload, {"HTTP_AUTHORIZATION": "Bearer test-token"})
        self.assertEqual(denied["status"], "401 Unauthorized")
        self.assertEqual(accepted["status"], "202 Accepted")
        self.assertTrue(json.loads(accepted["body"])["created"])

    @mock.patch("vuln_intel.dashboard.scan_service.request_inventory_initial_scan")
    @mock.patch("vuln_intel.dashboard.inventory_integration.register_repository")
    def test_inventory_registration_returns_first_scan_and_pipeline_credentials(
        self, register_repository, request_initial_scan
    ):
        repository = {
            "application_id": "gitlab:gitlab.internal.example:group:service",
            "name": "Group/Service",
            "repository_url": "https://gitlab.internal.example/Group/Service",
        }
        register_repository.return_value = {
            "repository": repository,
            "pipeline": {"trigger_url": "https://scanner.example/api/v1/scans", "credential": "ci-secret"},
            "callback": {"url": "https://inventory.example/callback", "signing_secret": "callback-secret"},
        }
        request_initial_scan.return_value = ({"run_id": "scan-1", "status": "queued"}, True)
        payload = {
            "external_inventory_id": "inventory-app-1",
            "repository_url": repository["repository_url"],
            "callback_url": "https://inventory.example/callback",
        }
        with mock.patch.object(config, "INVENTORY_API_TOKEN", "inventory-token"):
            response = self.request(
                "/api/v1/inventory/repositories",
                "POST",
                payload,
                {"HTTP_AUTHORIZATION": "Bearer inventory-token"},
            )
        self.assertEqual(response["status"], "202 Accepted")
        body = json.loads(response["body"])
        self.assertEqual(body["repository"], repository)
        self.assertEqual(body["initial_scan"]["run_id"], "scan-1")
        self.assertEqual(body["pipeline"]["credential"], "ci-secret")
        self.assertEqual(body["callback"]["signing_secret"], "callback-secret")
        request_initial_scan.assert_called_once_with(repository["application_id"], "inventory-app-1")

    @mock.patch("vuln_intel.dashboard.inventory_integration.register_repository")
    def test_inventory_registration_rejects_missing_bearer_authentication(self, register_repository):
        with mock.patch.object(config, "INVENTORY_API_TOKEN", "inventory-token"):
            response = self.request(
                "/api/v1/inventory/repositories",
                "POST",
                {"external_inventory_id": "inventory-app-1"},
            )
        self.assertEqual(response["status"], "401 Unauthorized")
        register_repository.assert_not_called()

    @mock.patch("vuln_intel.dashboard.scan_service.request_scan")
    @mock.patch("vuln_intel.dashboard.inventory_integration.authenticate_pipeline", return_value=True)
    def test_inventory_pipeline_trigger_queues_the_requested_commit(self, authenticate_pipeline, request_scan):
        request_scan.return_value = ({"run_id": "scan-2", "status": "queued"}, True)
        payload = {
            "commit_sha": "c" * 40,
            "ref": "feature/scan",
            "event_id": "pipeline-42",
        }
        response = self.request(
            "/api/v1/inventory/repositories/gitlab:gitlab.internal.example:group:service/scans",
            "POST",
            payload,
            {"HTTP_AUTHORIZATION": "Bearer ci-secret"},
        )
        self.assertEqual(response["status"], "202 Accepted")
        request_scan.assert_called_once_with({
            "application_id": "gitlab:gitlab.internal.example:group:service",
            **payload,
        })
        authenticate_pipeline.assert_called_once_with(
            "gitlab:gitlab.internal.example:group:service", "ci-secret"
        )

    @mock.patch("vuln_intel.dashboard.inventory_integration.rotate_pipeline_credential")
    def test_inventory_can_rotate_pipeline_credential(self, rotate_credential):
        rotate_credential.return_value = {
            "trigger_url": "https://scanner.example/scans",
            "credential": "new-secret",
        }
        with mock.patch.object(config, "INVENTORY_API_TOKEN", "inventory-token"):
            response = self.request(
                "/api/v1/inventory/repositories/gitlab:gitlab.internal.example:group:service/credential",
                "POST",
                headers={"HTTP_AUTHORIZATION": "Bearer inventory-token"},
            )
        self.assertEqual(response["status"], "200 OK")
        self.assertEqual(json.loads(response["body"])["pipeline"]["credential"], "new-secret")
        rotate_credential.assert_called_once_with("gitlab:gitlab.internal.example:group:service")

    def test_inventory_callback_requires_https_and_an_allowlisted_host(self):
        with mock.patch.object(config, "INVENTORY_CALLBACK_HOSTS", ["inventory.example"]):
            self.assertEqual(
                inventory_integration.validate_callback_url("https://inventory.example/hooks/scan"),
                "https://inventory.example/hooks/scan",
            )
            for value in (
                "http://inventory.example/hooks/scan",
                "https://unapproved.example/hooks/scan",
                "https://inventory.example/hooks/scan?secret=value",
            ):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    inventory_integration.validate_callback_url(value)

    @mock.patch("vuln_intel.inventory_integration.mark_callback_delivered")
    @mock.patch("vuln_intel.inventory_integration.repository_connections._decrypt_secret", return_value="signing-secret")
    @mock.patch("vuln_intel.inventory_integration.claim_callback_delivery")
    @mock.patch("vuln_intel.inventory_integration.urllib.request.build_opener")
    def test_inventory_callback_is_signed_and_marked_delivered(
        self, build_opener, claim_delivery, decrypt_secret, mark_delivered
    ):
        claim_delivery.return_value = {
            "event_id": "event-1",
            "callback_url": "https://inventory.example/callback",
            "encrypted_callback_secret": b"encrypted",
            "payload": {"event_id": "event-1", "event": "scan.completed"},
            "attempts": 1,
        }
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        opener = mock.MagicMock()
        opener.open.return_value = response
        build_opener.return_value = opener
        with mock.patch.object(config, "INVENTORY_CALLBACK_HOSTS", ["inventory.example"]):
            self.assertTrue(inventory_integration.deliver_callback_once())

        request = opener.open.call_args.args[0]
        body = request.data
        expected = hmac.new(b"signing-secret", body, hashlib.sha256).hexdigest()
        self.assertEqual(request.get_header("X-vuln-signature"), f"sha256={expected}")
        self.assertEqual(request.get_header("X-vuln-event-id"), "event-1")
        mark_delivered.assert_called_once_with("event-1")

    @mock.patch("vuln_intel.dashboard.scan_store.list_scan_runs", return_value=[])
    def test_scan_list_api_accepts_optional_application_filter(self, list_scan_runs):
        response = self.request("/api/scans", query="application_id=app-3")
        self.assertEqual(response["status"], "200 OK")
        list_scan_runs.assert_called_once_with("app-3", 50)

    @mock.patch("vuln_intel.dashboard.scan_service.request_latest_scan")
    @mock.patch("vuln_intel.dashboard.repository_connections.save_repository_connection")
    def test_github_url_scan_adds_repository_and_queues_latest_commit(self, save_connection, request_latest):
        repository = {
            "application_id": "github:acme:service",
            "name": "Acme/Service",
            "repository_url": "https://github.com/Acme/Service",
        }
        scan = {"run_id": "scan-1", "status": "queued"}
        save_connection.return_value = repository
        request_latest.return_value = (scan, True)

        response = self.request(
            "/api/repositories/scan", "POST", {"repository_url": "https://github.com/Acme/Service"}
        )

        self.assertEqual(response["status"], "202 Accepted")
        body = json.loads(response["body"])
        self.assertEqual(body["repository"], repository)
        self.assertEqual(body["scan"], scan)
        save_connection.assert_called_once_with(
            "github:acme:service", "https://github.com/Acme/Service", "Acme/Service"
        )
        request_latest.assert_called_once_with("github:acme:service")

    @mock.patch("vuln_intel.dashboard.scan_service.request_latest_scan")
    @mock.patch("vuln_intel.dashboard.repository_connections.save_repository_connection")
    def test_github_url_scan_rejects_non_github_urls(self, save_connection, request_latest):
        response = self.request(
            "/api/repositories/scan", "POST", {"repository_url": "https://gitlab.com/acme/service"}
        )
        self.assertEqual(response["status"], "400 Bad Request")
        save_connection.assert_not_called()
        request_latest.assert_not_called()

    @mock.patch("vuln_intel.dashboard.scan_service.request_latest_scan")
    @mock.patch("vuln_intel.dashboard.repository_connections.save_repository_connection")
    def test_github_url_scan_is_local_only(self, save_connection, request_latest):
        response = self.request(
            "/api/repositories/scan",
            "POST",
            {"repository_url": "https://github.com/acme/service"},
            {"REMOTE_ADDR": "192.0.2.10"},
        )
        self.assertEqual(response["status"], "403 Forbidden")
        save_connection.assert_not_called()
        request_latest.assert_not_called()

    @mock.patch("vuln_intel.dashboard.repository_connections.list_repository_connections")
    def test_repository_list_is_local_and_never_returns_credentials(self, list_connections):
        list_connections.return_value = [{
            "application_id": "app-1",
            "name": "Example",
            "repository_url": "https://github.com/acme/service",
            "updated_at": "2026-01-01T00:00:00Z",
        }]
        local = self.request("/api/repositories")
        remote = self.request("/api/repositories", headers={"REMOTE_ADDR": "192.0.2.10"})
        self.assertEqual(local["status"], "200 OK")
        self.assertEqual(remote["status"], "403 Forbidden")
        self.assertNotIn(b'"token"', local["body"])
        self.assertNotIn(b'"username"', local["body"])
        list_connections.assert_called_once()

    @mock.patch("vuln_intel.dashboard.repository_connections.save_repository_connection")
    def test_repository_save_needs_no_admin_token_and_stores_only_repository_details(self, save_connection):
        save_connection.return_value = {
            "application_id": "app-1",
            "repository_url": "https://github.com/acme/service",
        }
        payload = {
            "application_id": "app-1",
            "repository_url": "https://github.com/acme/service",
        }
        response = self.request("/api/repositories", "POST", payload)
        self.assertEqual(response["status"], "200 OK")
        save_connection.assert_called_once_with("app-1", "https://github.com/acme/service", "")

    @mock.patch("vuln_intel.dashboard.repository_connections.save_provider_credentials")
    def test_provider_credentials_are_saved_once_and_never_returned(self, save_credentials):
        save_credentials.return_value = {
            "provider": "github",
            "configured": True,
            "updated_at": "2026-01-01T00:00:00Z",
            "verification": {"status": "verified"},
        }
        payload = {"provider": "github", "username": "octocat", "token": "private-token"}
        allowed = self.request("/api/git-credentials", "POST", payload)
        self.assertEqual(allowed["status"], "200 OK")
        self.assertNotIn(b"octocat", allowed["body"])
        self.assertNotIn(b"private-token", allowed["body"])
        self.assertEqual(
            json.loads(allowed["body"])["credentials"]["verification"],
            {"status": "verified"},
        )
        save_credentials.assert_called_once_with("github", "octocat", "private-token")

    @mock.patch(
        "vuln_intel.dashboard.repository_connections.save_provider_credentials",
        side_effect=repository_connections.ProviderCredentialVerificationError("GitHub rejected this token."),
    )
    def test_invalid_github_credentials_are_not_saved(self, save_credentials):
        payload = {"provider": "github", "username": "octocat", "token": "invalid-token"}
        response = self.request("/api/git-credentials", "POST", payload)
        self.assertEqual(response["status"], "422 Unprocessable Entity")
        self.assertIn(b"GitHub rejected this token.", response["body"])
        save_credentials.assert_called_once_with("github", "octocat", "invalid-token")

    @mock.patch(
        "vuln_intel.dashboard.repository_connections.save_provider_credentials",
        side_effect=repository_connections.ProviderCredentialVerificationUnavailable("GitHub is unavailable."),
    )
    def test_github_verification_outage_is_reported_as_unavailable(self, save_credentials):
        payload = {"provider": "github", "username": "octocat", "token": "private-token"}
        response = self.request("/api/git-credentials", "POST", payload)
        self.assertEqual(response["status"], "503 Service Unavailable")
        self.assertIn(b"GitHub is unavailable.", response["body"])
        save_credentials.assert_called_once_with("github", "octocat", "private-token")

    @mock.patch("vuln_intel.dashboard.repository_connections.list_provider_credentials")
    def test_provider_credential_list_returns_status_only(self, list_credentials):
        list_credentials.return_value = [
            {"provider": "github", "configured": True, "updated_at": "2026-01-01T00:00:00Z"},
            {"provider": "gitlab", "configured": False, "updated_at": None},
        ]
        response = self.request("/api/git-credentials")
        self.assertEqual(response["status"], "200 OK")
        self.assertNotIn(b"token", response["body"])
        self.assertNotIn(b"username", response["body"])

    @mock.patch("vuln_intel.dashboard.scan_service.request_latest_scan")
    @mock.patch("vuln_intel.dashboard.repository_connections.get_repository_connection")
    def test_manual_repository_scan_needs_no_admin_token_and_queues_latest(self, get_connection, request_latest):
        get_connection.return_value = {"application_id": "app-1"}
        request_latest.return_value = ({"run_id": "scan-1", "status": "queued"}, True)
        accepted = self.request("/api/repositories/app-1/scan", "POST")
        self.assertEqual(accepted["status"], "202 Accepted")
        request_latest.assert_called_once_with("app-1")


if __name__ == "__main__":
    unittest.main()
