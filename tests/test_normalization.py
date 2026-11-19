import unittest

from vuln_intel.normalization.cvss import cvss3_score, make_cvss, severity_label
from vuln_intel.normalization.ecosystems import std_ecosystem, std_package
from vuln_intel.normalization.mappers import NORMALIZERS
from vuln_intel.normalization.mappers.nvd import normalize_nvd
from vuln_intel.normalization.resolver import Store, expand_views, pick_canonical
from vuln_intel.normalization.schema import validate_view
from vuln_intel.normalization.versions import osv_events_to_intervals, parse_constraint_range
from vuln_intel.utils import parse_ts, utcnow


class CvssTests(unittest.TestCase):
    def test_known_scores(self):
        self.assertEqual(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)  # Log4Shell
        self.assertEqual(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5)
        self.assertEqual(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)

    def test_garbage_vector_is_none(self):
        self.assertIsNone(cvss3_score("not a vector"))

    def test_labels(self):
        self.assertEqual([severity_label(s) for s in (0, 3.9, 4, 6.9, 7, 8.9, 9, 10)],
                         ["NONE", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"])

    def test_make_cvss_fills_score_and_moderate_alias(self):
        c = make_cvss(None, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None, None, "osv")
        self.assertEqual((c["version"], c["score"], c["severity"]), ("3.1", 9.8, "CRITICAL"))
        self.assertEqual(make_cvss("2.0", None, 5.0, "MODERATE", "x")["severity"], "MEDIUM")


class EcosystemTests(unittest.TestCase):
    def test_names(self):
        self.assertEqual(std_ecosystem("pip"), ("PyPI", None))
        self.assertEqual(std_ecosystem("Debian:12"), ("Debian", "12"))
        self.assertEqual(std_ecosystem("RUST")[0], "crates.io")
        self.assertEqual(std_ecosystem("SomethingNew")[0], "SomethingNew")

    def test_package_names(self):
        self.assertEqual(std_package("PyPI", "Django_Rest.Framework"), "django-rest-framework")
        self.assertEqual(std_package("npm", "Lodash"), "lodash")
        self.assertEqual(std_package("Maven", "org.Apache:Log4j"), "org.Apache:Log4j")  # case kept


class VersionRangeTests(unittest.TestCase):
    def test_osv_events(self):
        ivs = osv_events_to_intervals([{"introduced": "0"}, {"fixed": "1.2.3"}, {"introduced": "2.0"}, {"last_affected": "2.5"}])
        self.assertEqual([i["expr"] for i in ivs], ["<1.2.3", ">=2.0, <=2.5"])

    def test_open_ended_and_fixed_only(self):
        self.assertEqual(osv_events_to_intervals([{"introduced": "3.0"}])[0]["expr"], ">=3.0")
        self.assertEqual(osv_events_to_intervals([{"fixed": "1.0"}])[0]["expr"], "<1.0")

    def test_github_constraints(self):
        self.assertEqual(parse_constraint_range(">= 2.0-beta9, < 2.15.0")["expr"], ">=2.0-beta9, <2.15.0")
        self.assertEqual(parse_constraint_range("< 4.17.21")["expr"], "<4.17.21")
        self.assertEqual(parse_constraint_range("= 1.0.0")["expr"], "==1.0.0")
        self.assertEqual(parse_constraint_range("> 1.0, <= 2.0")["expr"], ">1.0, <=2.0")
        self.assertIsNone(parse_constraint_range("whatever"))

    def test_same_interval_from_two_sources_has_same_expr(self):
        osv = osv_events_to_intervals([{"introduced": "1.0"}, {"fixed": "1.5"}])[0]["expr"]
        ghsa = parse_constraint_range(">= 1.0, < 1.5")["expr"]
        self.assertEqual(osv, ghsa)


class NvdAffectedMappingTests(unittest.TestCase):
    def test_nvd_keeps_platform_and_advisory_version_range(self):
        record = {
            "id": "CVE-2026-40895",
            "affected": [{
                "affectedData": [{
                    "vendor": "follow-redirects",
                    "product": "follow-redirects",
                    "versions": [{"version": "< 1.16.0", "status": "affected"}],
                }],
            }],
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:follow-redirects_project:follow-redirects:*:*:*:*:*:node.js:*:*",
                        "versionEndExcluding": "1.16.0",
                    }],
                }],
            }],
        }

        normalized = normalize_nvd(record)
        node_entry = next(item for item in normalized["affected"] if item.get("target_sw") == "node.js")

        self.assertEqual(node_entry["package"], "follow-redirects")
        self.assertEqual(node_entry["ranges"][0]["expr"], "<1.16.0")

    def test_nvd_affected_range_prevents_cpe_update_from_becoming_stable_version(self):
        record = {
            "id": "CVE-2026-42304",
            "affected": [{
                "affectedData": [{
                    "vendor": "twisted",
                    "product": "twisted",
                    "versions": [{"version": "< 26.4.0rc2", "status": "affected"}],
                }],
            }],
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:twisted:twisted:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "26.4.0",
                        },
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:twisted:twisted:26.4.0:rc1:*:*:*:*:*:*",
                        },
                    ],
                }],
            }],
        }

        normalized = normalize_nvd(record)
        twisted = next(item for item in normalized["affected"] if item["vendor"] == "twisted")
        expressions = {item["expr"] for item in twisted["ranges"]}

        self.assertIn("<26.4.0rc2", expressions)
        self.assertIn("==26.4.0-rc1", expressions)
        self.assertNotIn("==26.4.0", expressions)


class TimestampTests(unittest.TestCase):
    def test_formats(self):
        for s in ("2026-11-10T08:30:00Z", "2026-11-10T08:30:00.000", "2026-11-10T09:30:00+01:00",
                  "2026-11-10T08:30:00.1234567Z", "2026-11-10"):
            self.assertIsNotNone(parse_ts(s), s)
        self.assertEqual(parse_ts("2026-11-10T09:30:00+01:00"), parse_ts("2026-11-10T08:30:00Z"))
        self.assertIsNone(parse_ts("garbage"))


def view(source, sid, ids, modified="2026-11-10T00:00:00Z", **kw):
    v = NORMALIZERS.get(source) and None
    from vuln_intel.normalization.schema import new_view
    v = new_view(source, sid)
    v.update(ids=ids, modified=modified, **kw)
    assert not validate_view(v)
    return v


class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.store = Store({"vulnerabilities": {}}, {}, utcnow())

    def feed(self, *views):
        for v in views:
            for x in expand_views(v):
                self.store.upsert(x)
        self.store.finalize()
        return self.store.ents

    def test_alias_merge_and_canonical_id(self):
        ents = self.feed(view("ghsa", "GHSA-aaaa-bbbb-cccc", ["GHSA-aaaa-bbbb-cccc"]),
                         view("osv", "GHSA-aaaa-bbbb-cccc", ["GHSA-aaaa-bbbb-cccc", "CVE-2024-1111"]))
        self.assertEqual(list(ents), ["CVE-2024-1111"])  # entity re-keyed from GHSA to CVE
        self.assertEqual(ents["CVE-2024-1111"]["sources"], ["ghsa", "osv"])

    def test_record_bridging_two_entities_merges_them(self):
        self.feed(view("nvd", "CVE-2024-2222", ["CVE-2024-2222"]),
                  view("ghsa", "GHSA-xxxx-yyyy-zzzz", ["GHSA-xxxx-yyyy-zzzz"]))
        self.assertEqual(len(self.store.ents), 2)
        self.store.new_ids.clear()
        ents = self.feed(view("osv", "OSV-1", ["OSV-1", "CVE-2024-2222", "GHSA-xxxx-yyyy-zzzz"]))
        self.assertEqual(list(ents), ["CVE-2024-2222"])
        self.assertEqual(sorted(ents["CVE-2024-2222"]["sources"]), ["ghsa", "nvd", "osv"])

    def test_bundled_cves_are_not_glued_together(self):
        ents = self.feed(view("osv", "DSA-9999-1", ["DSA-9999-1", "CVE-2024-3001", "CVE-2024-3002"]))
        self.assertEqual(sorted(ents), ["CVE-2024-3001", "CVE-2024-3002"])

    def test_stale_and_unchanged_contributions(self):
        self.feed(view("nvd", "CVE-2024-4000", ["CVE-2024-4000"], modified="2026-11-10T00:00:00Z", description="new"))
        before = dict(self.store.stats)
        self.feed(view("nvd", "CVE-2024-4000", ["CVE-2024-4000"], modified="2026-11-09T00:00:00Z", description="older"))
        self.assertEqual(self.store.stats["stale"], before["stale"] + 1)
        self.assertEqual(self.store.ents["CVE-2024-4000"]["description"], "new")
        self.feed(view("nvd", "CVE-2024-4000", ["CVE-2024-4000"], modified="2026-11-10T00:00:00Z", description="new"))
        self.assertEqual(self.store.stats["unchanged"], 1)

    def test_update_replaces_old_source_data(self):
        r1 = [{"introduced": "0", "fixed": "1.0", "expr": "<1.0"}]
        r2 = [{"introduced": "0", "fixed": "1.1", "expr": "<1.1"}]
        mk = lambda rngs, mod: view("osv", "PYSEC-1", ["PYSEC-1", "CVE-2024-5000"], modified=mod, affected=[
            {"ecosystem": "PyPI", "release": None, "package": "x", "scheme": "pep440", "ranges": rngs, "versions": [], "patched": []}])
        self.feed(mk(r1, "2026-11-01T00:00:00Z"))
        ents = self.feed(mk(r2, "2026-11-02T00:00:00Z"))
        self.assertEqual([r["expr"] for r in ents["CVE-2024-5000"]["affected"][0]["ranges"]], ["<1.1"])

    def test_pick_canonical(self):
        self.assertEqual(pick_canonical(["GHSA-a", "CVE-2024-0009", "CVE-2024-0001"]), "CVE-2024-0001")
        self.assertEqual(pick_canonical(["PYSEC-1", "GHSA-a"]), "GHSA-a")


class ValidationTests(unittest.TestCase):
    def test_rejects_bad_records(self):
        from vuln_intel.normalization.schema import new_view
        v = new_view("osv", "X-1")
        self.assertIn("no identifiers", validate_view(v))
        v.update(ids=["X-1"])
        self.assertIn("no modified/published timestamp", validate_view(v))
        v.update(modified="2026-01-01T00:00:00Z", cvss=[{"score": 11}])
        self.assertTrue(any("out of range" in e for e in validate_view(v)))


if __name__ == "__main__":
    unittest.main()
