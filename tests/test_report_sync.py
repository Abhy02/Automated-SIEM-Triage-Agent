import os
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from report_sync.report_monitor import ReportMonitor
from report_sync.report_cache import ReportCacheManager
from report_sync.report_generator import ReportGenerator
from report_sync.refresh_service import ReportRefreshService


class TestReportSyncModule(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.patcher_cache = patch("report_sync.report_cache.CACHE_DIR", self.temp_dir)
        self.patcher_cache.start()

    def tearDown(self):
        self.patcher_cache.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_report_monitor_hash(self):
        monitor = ReportMonitor()
        sample_hit = {
            "_id": "doc_101",
            "_source": {
                "@timestamp": "2026-08-04T12:00:00Z",
                "rule": {"id": "5710", "level": 10, "description": "SSH Brute Force"},
                "agent": {"name": "test-agent", "ip": "192.168.1.50"},
                "data": {"srcip": "10.0.0.99"}
            }
        }
        h1 = monitor.compute_alert_hash(sample_hit)
        self.assertIsNotNone(h1)
        self.assertEqual(len(h1), 64)

        # Mutate data and verify hash change
        sample_hit["_source"]["data"]["srcip"] = "10.0.0.100"
        h2 = monitor.compute_alert_hash(sample_hit)
        self.assertNotEqual(h1, h2)

    def test_report_cache_manager_classification(self):
        cache_mgr = ReportCacheManager()
        sample_data = {
            "generated_at": "2026-08-04 12:00:00 UTC",
            "risk": "High",
            "alert": {"timestamp": "2026-08-04 12:00:00"}
        }

        # Store initial report
        cache_mgr.store_cached_report("doc_202", sample_data, evidence_hash="hash_v1")
        cached = cache_mgr.get_report_with_metadata("doc_202")
        self.assertIsNotNone(cached)
        self.assertEqual(cached.get("report_status"), "Latest")

        # Mark outdated on evidence change
        is_outdated = cache_mgr.mark_outdated_if_evidence_changed("doc_202", "hash_v2")
        self.assertTrue(is_outdated)

        outdated_data = cache_mgr.get_report_with_metadata("doc_202")
        self.assertTrue(outdated_data.get("is_outdated"))
        self.assertIn("⚠ New alert data available", outdated_data.get("outdated_message"))

    @patch("report_sync.report_generator.investigate_alert")
    def test_report_generator_metadata_refresh(self, mock_investigate):
        mock_investigate.return_value = {
            "risk": "Critical",
            "alert": {"rule_id": "5503", "agent_name": "db-server", "src_ip": "1.2.3.4"},
            "mitre": {"technique": "T1078"},
            "intel": {"virus_total": "Clean"},
            "iocs": ["1.2.3.4"],
            "report": {"summary": "Critical alert investigation", "timeline": []}
        }

        cache_mgr = ReportCacheManager()
        generator = ReportGenerator(cache_mgr)

        report = generator.generate_or_get_report("doc_303", force_regenerate=True, evidence_hash="hash_303")
        self.assertIsNotNone(report)
        self.assertEqual(report.get("risk_score"), "Critical")
        self.assertIn("metadata_refreshed_at", report)
        self.assertEqual(report.get("evidence", {}).get("rule_id"), "5503")

    @patch.object(ReportMonitor, "scan_for_alerts")
    def test_refresh_service_sync_now(self, mock_scan):
        mock_scan.return_value = {
            "new_alerts": [{"_id": "doc_999", "_source": {}}],
            "updated_alerts": [],
            "last_timestamp": "2026-08-04 15:00:00 IST",
            "total_count": 1
        }

        service = ReportRefreshService(check_interval=100)
        stats = service.sync_now()

        self.assertEqual(stats["total_alerts_seen"], 1)
        self.assertEqual(stats["last_alert_timestamp"], "2026-08-04 15:00:00 IST")


if __name__ == "__main__":
    unittest.main()
