import unittest

from vuln_intel.asset_store import _validated_fields


class AssetValidationTests(unittest.TestCase):
    def test_create_defaults_optional_fields_and_normalizes_text(self):
        asset = _validated_fields({
            "asset_type": "endpoint",
            "name": "  Finance laptop ",
            "identifier": " FIN-LT-01 ",
        })
        self.assertEqual(asset["name"], "Finance laptop")
        self.assertEqual(asset["identifier"], "FIN-LT-01")
        self.assertEqual(asset["status"], "active")
        self.assertEqual(asset["criticality"], "unknown")
        self.assertEqual(asset["owner"], "")

    def test_create_rejects_invalid_type_and_duplicate_unfit_fields(self):
        with self.assertRaisesRegex(ValueError, "asset type"):
            _validated_fields({
                "asset_type": "workstation",
                "name": "Finance laptop",
                "identifier": "FIN-LT-01",
            })
        with self.assertRaisesRegex(ValueError, "at most"):
            _validated_fields({
                "asset_type": "endpoint",
                "name": "x" * 201,
                "identifier": "FIN-LT-01",
            })

    def test_patch_rejects_empty_payload_and_non_text_fields(self):
        with self.assertRaisesRegex(ValueError, "At least one"):
            _validated_fields({}, partial=True)
        with self.assertRaisesRegex(TypeError, "Owner must be text"):
            _validated_fields({"owner": 42}, partial=True)


if __name__ == "__main__":
    unittest.main()
