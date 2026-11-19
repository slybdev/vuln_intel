import unittest
from datetime import datetime, time, timezone
from unittest import mock

from vuln_intel import feed_schedule


class FeedScheduleTests(unittest.TestCase):
    def test_schedule_time_requires_24_hour_hh_mm(self):
        for invalid_time in ("2:00", "24:00", "12:60", "12:00:00"):
            with self.subTest(invalid_time=invalid_time):
                with self.assertRaises(ValueError):
                    feed_schedule.save_schedule(True, invalid_time)
        with self.assertRaises(ValueError):
            feed_schedule.save_schedule("true", "02:00")

    def test_next_run_uses_the_next_utc_occurrence(self):
        now = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(
            feed_schedule._next_run_at(time(13, 30), now),
            datetime(2026, 11, 17, 13, 30, tzinfo=timezone.utc),
        )
        self.assertEqual(
            feed_schedule._next_run_at(time(11, 30), now),
            datetime(2026, 11, 18, 11, 30, tzinfo=timezone.utc),
        )

    @mock.patch("vuln_intel.feed_schedule._finish_run")
    @mock.patch("vuln_intel.feed_schedule.run_process")
    @mock.patch("vuln_intel.feed_schedule.run_collect")
    @mock.patch("vuln_intel.feed_schedule._claim_due_schedule")
    def test_due_schedule_collects_and_processes_all_sources(
        self, claim_due, run_collect, run_process, finish_run
    ):
        scheduled_at = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
        claim_due.return_value = scheduled_at
        run_collect.return_value = ("20261117T120000Z", False)

        self.assertTrue(feed_schedule.run_due_schedule())

        run_collect.assert_called_once_with(set(feed_schedule.ORDER))
        run_process.assert_called_once_with(only_runs=["20261117T120000Z"])
        finish_run.assert_called_once_with(
            scheduled_at,
            "succeeded",
            "20261117T120000Z",
            None,
        )

    @mock.patch("vuln_intel.feed_schedule._finish_run")
    @mock.patch("vuln_intel.feed_schedule.run_process")
    @mock.patch("vuln_intel.feed_schedule.run_collect")
    @mock.patch("vuln_intel.feed_schedule._claim_due_schedule")
    def test_incomplete_feed_run_is_reported_as_partial(
        self, claim_due, run_collect, run_process, finish_run
    ):
        scheduled_at = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
        claim_due.return_value = scheduled_at
        run_collect.return_value = ("20261117T120000Z", True)

        self.assertTrue(feed_schedule.run_due_schedule())

        finish_run.assert_called_once_with(
            scheduled_at,
            "partial",
            "20261117T120000Z",
            "One or more external feeds returned incomplete data. Review Security Logs.",
        )

    @mock.patch("vuln_intel.feed_schedule._finish_run")
    @mock.patch("vuln_intel.feed_schedule.run_collect", side_effect=RuntimeError("test failure"))
    @mock.patch("vuln_intel.feed_schedule._claim_due_schedule")
    def test_pipeline_failure_is_recorded(
        self, claim_due, run_collect, finish_run
    ):
        scheduled_at = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
        claim_due.return_value = scheduled_at

        with self.assertLogs("vuln_intel.feed_schedule", level="ERROR"):
            self.assertTrue(feed_schedule.run_due_schedule())

        finish_run.assert_called_once_with(
            scheduled_at,
            "failed",
            None,
            "Scheduled feed refresh failed. Check the backend logs for details.",
        )

    @mock.patch("vuln_intel.feed_schedule._claim_due_schedule", return_value=None)
    def test_no_due_schedule_does_not_run_pipeline(self, claim_due):
        with mock.patch("vuln_intel.feed_schedule.run_collect") as run_collect:
            self.assertFalse(feed_schedule.run_due_schedule())
        run_collect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
