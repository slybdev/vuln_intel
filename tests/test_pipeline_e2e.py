"""End-to-end: every source is faked at the single HTTP choke point (vuln_intel.http_client.http_get)."""
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vuln_intel import config
from vuln_intel.pipeline import run_collect, run_process
from vuln_intel.utils import iso, read_json, utcnow

LOG4J = "CVE-2021-44228"
NOW = iso(utcnow())
VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

NVD = {"totalResults": 1, "vulnerabilities": [{"cve": {
    "id": LOG4J, "published": "2021-12-10T10:15:09.143", "lastModified": NOW.replace("Z", ".000"),
    "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."}],
    "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
        "version": "3.1", "vectorString": VEC, "baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}, {"lang": "en", "value": "NVD-CWE-Other"}]}],
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "2.0-beta9", "versionEndExcluding": "2.15.0"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*"}]}]}],
    "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}]}}]}

OSV_LOG4J = {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": [LOG4J], "summary": "Remote code injection in Log4j",
             "modified": NOW, "published": "2021-12-10T00:00:00Z",
             "severity": [{"type": "CVSS_V3", "score": VEC}],
             "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-502", "CWE-400"]},
             "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                           "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]}]}],
             "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}, {"url": "https://example.com/extra"}]}
OSV_BUNDLE = {"id": "PYSEC-2099-1", "aliases": ["CVE-2099-0001", "CVE-2099-0002"], "modified": NOW,
              "details": "bundle", "affected": [{"package": {"ecosystem": "PyPI", "name": "Some_Pkg"},
                                                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2"}]}]}]}
OSV_BAD = {"id": "BROKEN-1", "aliases": []}  # no "modified" -> must be rejected, not crash the run

GHSA = [
    {"ghsa_id": "GHSA-jfh8-c2jp-5v3q", "cve_id": LOG4J, "summary": "Remote code injection in Log4j",
     "severity": "critical", "updated_at": NOW, "published_at": "2021-12-10T00:00:00Z",
     "identifiers": [{"type": "GHSA", "value": "GHSA-jfh8-c2jp-5v3q"}, {"type": "CVE", "value": LOG4J}],
     "cvss_severities": {"cvss_v3": {"vector_string": VEC, "score": 10.0}},
     "cwes": [{"cwe_id": "CWE-502"}], "references": ["https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"],
     "vulnerabilities": [{"package": {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core"},
                          "vulnerable_version_range": ">= 2.0-beta9, < 2.15.0", "first_patched_version": "2.15.0"}]},
    {"ghsa_id": "GHSA-abcd-efgh-2345", "cve_id": None, "summary": "Prototype pollution", "severity": "moderate",
     "updated_at": NOW, "identifiers": [{"type": "GHSA", "value": "GHSA-abcd-efgh-2345"}], "cwes": [], "references": [],
     "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "Some-Lib"}, "vulnerable_version_range": "< 4.17.21",
                          "first_patched_version": {"identifier": "4.17.21"}}]},
]
KEV = {"catalogVersion": "2026.11.10", "count": 2, "vulnerabilities": [
    {"cveID": LOG4J, "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Apache Log4j2 RCE",
     "dateAdded": "2021-12-10", "shortDescription": "kev desc", "requiredAction": "Apply updates.",
     "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known", "notes": "", "cwes": ["CWE-502"]},
    {"cveID": "CVE-2023-0001", "vendorProject": "X", "product": "Y", "vulnerabilityName": "n", "dateAdded": "2023-01-01",
     "shortDescription": "d", "requiredAction": "r", "dueDate": "2023-01-22", "knownRansomwareCampaignUse": "Unknown"}]}
EPSS_CSV = ("#model_version:v2025.03.14,score_date:2026-11-11T12:55:00Z\ncve,epss,percentile\n"
            f"{LOG4J},0.94358,0.99985\nCVE-2099-0001,0.00012,0.01\nCVE-1999-0001,0.5,0.9\n")


class FakeInternet:
    def __init__(self):
        self.fail_osv_ecosystem = None
        self.calls = []

    def __call__(self, url, headers=None, params=None, **kw):
        self.calls.append(url)
        old = "2020-01-01T00:00:00Z"
        if url.startswith(config.NVD_URL):
            return json.dumps(NVD).encode(), {}
        if url.endswith("/Maven/modified_id.csv"):
            if self.fail_osv_ecosystem == "Maven":
                raise RuntimeError("boom")
            return f"{NOW},Maven/GHSA-jfh8-c2jp-5v3q\n{old},GHSA-ancient\n".encode(), {}  # prefixed-id variant
        if url.endswith("/PyPI/modified_id.csv"):
            return f"{NOW},PYSEC-2099-1\n{NOW},BROKEN-1\n".encode(), {}
        if url.endswith("/Maven/GHSA-jfh8-c2jp-5v3q.json"):
            return json.dumps(OSV_LOG4J).encode(), {}
        if url.endswith("/PyPI/PYSEC-2099-1.json"):
            return json.dumps(OSV_BUNDLE).encode(), {}
        if url.endswith("/PyPI/BROKEN-1.json"):
            return json.dumps(OSV_BAD).encode(), {}
        if url.startswith(config.GHSA_URL):
            return json.dumps(GHSA).encode(), {"link": ""}
        if url == config.KEV_URL:
            return json.dumps(KEV).encode(), {}
        if url == config.EPSS_URL:
            return gzip.compress(EPSS_CSV.encode()), {}
        raise AssertionError(f"unexpected URL {url}")


class PipelineE2ETests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._old = config.DATA_DIR, config.OSV_ECOSYSTEMS
        config.set_data_dir(self.tmp.name)
        config.OSV_ECOSYSTEMS = ["Maven", "PyPI"]
        self.net = FakeInternet()
        for target in (mock.patch("vuln_intel.http_client.http_get", self.net),
                       mock.patch("vuln_intel.collectors.nvd.time.sleep")):
            target.start()
            self.addCleanup(target.stop)
        self.addCleanup(lambda: (config.set_data_dir(self._old[0]), setattr(config, "OSV_ECOSYSTEMS", self._old[1])))
        self.all = {"nvd", "osv", "ghsa", "kev", "epss"}

    def db(self):
        return read_json(config.DB_PATH, None)["vulnerabilities"]

    def test_full_run_builds_standardized_entity(self):
        run_id, failed = run_collect(self.all)
        self.assertFalse(failed)  # a bad OSV record is a processing reject, not a collection failure
        run_process()
        db = self.db()
        e = db[LOG4J]
        self.assertEqual(e["sources"], ["cisa_kev", "epss", "ghsa", "nvd", "osv"])
        self.assertIn("GHSA-jfh8-c2jp-5v3q", e["ids"])
        self.assertEqual((e["severity"], e["cvss_best"]["score"]), ("CRITICAL", 10.0))
        self.assertTrue(e["exploitation"]["in_kev"])
        self.assertTrue(e["exploitation"]["kev"]["known_ransomware_use"])
        self.assertEqual(e["exploitation"]["epss"], {"score": 0.94358, "percentile": 0.99985, "date": "2026-11-11"})
        self.assertEqual(e["cwes"], ["CWE-400", "CWE-502"])  # NVD-CWE-Other dropped, union of sources
        maven = next(a for a in e["affected"] if a["ecosystem"] == "Maven")
        self.assertEqual([r["expr"] for r in maven["ranges"]], [">=2.0-beta9, <2.15.0"])  # OSV + GHSA collapsed
        self.assertEqual(maven["patched"], ["2.15.0"])
        self.assertEqual(maven["sources"], ["ghsa", "osv"])
        cpe = next(a for a in e["affected"] if a["ecosystem"] == "cpe")
        self.assertEqual((cpe["vendor"], cpe["package"]), ("apache", "log4j"))  # non-vulnerable debian match ignored
        self.assertEqual(len(e["references"]), 3)

    def test_bundle_fanout_orphan_ghsa_and_kev_only_stub(self):
        run_collect(self.all)
        run_process()
        db = self.db()
        self.assertIn("CVE-2099-0001", db)
        self.assertIn("CVE-2099-0002", db)
        self.assertEqual(db["CVE-2099-0001"]["affected"][0]["package"], "some-pkg")  # PEP 503 normalization
        self.assertEqual(db["CVE-2099-0001"]["exploitation"]["epss"]["score"], 0.00012)
        self.assertEqual(db["GHSA-abcd-efgh-2345"]["severity"], "MEDIUM")  # "moderate" standardized
        self.assertEqual(db["GHSA-abcd-efgh-2345"]["affected"][0]["package"], "some-lib")
        self.assertEqual(db["GHSA-abcd-efgh-2345"]["affected"][0]["patched"], ["4.17.21"])
        self.assertTrue(db["CVE-2023-0001"]["exploitation"]["in_kev"])  # KEV-only stub entity
        self.assertNotIn("CVE-1999-0001", db)  # EPSS rows for CVEs we never saw are not imported

    def test_invalid_record_rejected_not_fatal(self):
        run_id, _ = run_collect(self.all)
        run_process()
        rejected = read_json(config.DATA_DIR / "rejected" / f"{run_id}.json", [])
        self.assertEqual([r["record_id"] for r in rejected], ["BROKEN-1"])
        self.assertIn("KeyError", rejected[0]["reason"])
        self.assertTrue((config.DATA_DIR / "reports" / f"report_{run_id}.txt").exists())

    def test_second_run_is_idempotent_and_kev_diffs(self):
        run_collect(self.all)
        run_process()
        first = self.db()
        run_id2, _ = run_collect(self.all)
        kev_raw = read_json(config.DATA_DIR / "raw" / run_id2 / "kev.json", {})
        self.assertEqual(kev_raw["count"], 0)  # nothing new in KEV since the last snapshot
        run_process()
        second = self.db()
        self.assertEqual(sorted(first), sorted(second))
        self.assertEqual({k: v["content_hash"] for k, v in first.items()},
                         {k: v["content_hash"] for k, v in second.items()})

    def test_partial_failure_does_not_advance_watermark(self):
        self.net.fail_osv_ecosystem = "Maven"
        _, failed = run_collect(self.all)
        self.assertTrue(failed)
        state = read_json(config.STATE_PATH, {})
        self.assertNotIn("watermark", state["sources"]["osv"])
        self.assertIn("watermark", state["sources"]["nvd"])  # other sources unaffected
        self.net.fail_osv_ecosystem = None
        _, failed = run_collect(self.all)
        self.assertFalse(failed)
        self.assertIn("watermark", read_json(config.STATE_PATH, {})["sources"]["osv"])

    def test_one_source_down_does_not_block_others(self):
        orig = self.net.__call__
        def flaky(url, *a, **k):
            if url == config.KEV_URL:
                raise RuntimeError("kev down")
            return orig(url, *a, **k)
        with mock.patch("vuln_intel.http_client.http_get", flaky):
            _, failed = run_collect(self.all)
        self.assertTrue(failed)
        run_process()
        self.assertIn(LOG4J, self.db())
        self.assertFalse(self.db()[LOG4J]["exploitation"]["in_kev"])

    def test_process_reads_each_run_once(self):
        run_collect({"nvd"})
        run_process()
        meta = read_json(config.DB_PATH, None)["meta"]
        run_process()  # nothing pending
        self.assertEqual(read_json(config.DB_PATH, None)["meta"], meta)


if __name__ == "__main__":
    unittest.main()
