import unittest
from unittest import mock

from vuln_intel import event_store


class EventStoreTests(unittest.TestCase):
    def setUp(self):
        self.conn = mock.MagicMock()
        self.cursor = mock.MagicMock()
        self.conn.cursor.return_value.__enter__.return_value = self.cursor

    @mock.patch("vuln_intel.event_store.backfill_existing_events")
    @mock.patch("vuln_intel.event_store._ensure_schema")
    @mock.patch("vuln_intel.event_store._connect")
    def test_event_list_applies_search_filters_and_pagination(
        self, connect, ensure_schema, backfill
    ):
        connect.return_value = (self.conn, None)
        self.cursor.fetchone.return_value = (31,)
        self.cursor.fetchall.return_value = []

        result = event_store.list_events("router", "HIGH", "scan", 2, 10)

        self.assertEqual(result, {"items": [], "total": 31, "page": 2, "page_size": 10})
        sql, params = self.cursor.execute.call_args_list[0].args
        self.assertIn("message ILIKE", sql)
        self.assertIn("severity = %s", sql)
        self.assertIn("category = %s", sql)
        self.assertEqual(params, ("%router%",) * 5 + ("HIGH", "scan"))
        self.assertEqual(
            self.cursor.execute.call_args_list[1].args[1],
            ("%router%",) * 5 + ("HIGH", "scan", 10, 10),
        )
        backfill.assert_called_once()

    @mock.patch("vuln_intel.event_store._ensure_schema")
    @mock.patch("vuln_intel.event_store._connect")
    def test_summary_reports_actual_database_aggregates(self, connect, ensure_schema):
        connect.return_value = (self.conn, None)
        self.cursor.fetchone.return_value = (8, 3, 2, 1)

        result = event_store.get_event_summary()

        self.assertEqual(
            result,
            {"total": 8, "last_24_hours": 3, "high_severity": 2, "failed": 1},
        )


if __name__ == "__main__":
    unittest.main()
