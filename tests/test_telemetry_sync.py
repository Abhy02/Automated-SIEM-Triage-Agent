import unittest
from unittest.mock import patch, MagicMock

from telemetry.logger import SensitiveDataFilter, log_telemetry_event
from telemetry.connection_manager import TelemetryConnectionManager
from telemetry.cache_manager import TelemetryCacheManager
from telemetry.alert_sync import AlertSyncEngine
from telemetry.recovery import TelemetryRecoveryEngine
from telemetry.alert_monitor import BackgroundAlertMonitor, start_telemetry_monitor


class TestTelemetryLogger(unittest.TestCase):
    def test_sensitive_data_filter(self):
        filt = SensitiveDataFilter()
        record = MagicMock()
        record.msg = "OpenSearch connecting with auth='admin:SecretPassword123' token='bearer123'"
        filt.filter(record)
        self.assertNotIn("SecretPassword123", record.msg)
        self.assertNotIn("bearer123", record.msg)
        self.assertIn("[REDACTED]", record.msg)

    def test_log_telemetry_event(self):
        log_telemetry_event(
            event_type="TEST_SYNC",
            opensearch_connected=True,
            wazuh_api_connected=True,
            latest_timestamp="2026-08-06T11:40:00.000Z",
            latest_doc_id="doc123",
            new_alerts_found=True,
            cache_invalidated=True,
            message="Unit test log verification"
        )


class TestTelemetryConnectionManager(unittest.TestCase):
    def test_connection_verification(self):
        conn_mgr = TelemetryConnectionManager()
        self.assertIsInstance(conn_mgr.verify_opensearch(), bool)
        self.assertIsInstance(conn_mgr.verify_wazuh_api(), bool)


class TestTelemetryCacheManager(unittest.TestCase):
    def test_inspect_and_update(self):
        cache_mgr = TelemetryCacheManager()
        fake_hits_1 = [
            {"_id": "doc1", "_source": {"@timestamp": "2026-08-06T11:00:00.000Z"}}
        ]
        fake_hits_2 = [
            {"_id": "doc2", "_source": {"@timestamp": "2026-08-06T11:05:00.000Z"}}
        ]

        # First hit should register as new
        self.assertTrue(cache_mgr.inspect_and_update(fake_hits_1))
        # Same hit should not register as new
        self.assertFalse(cache_mgr.inspect_and_update(fake_hits_1))
        # Newer hit should register as new
        self.assertTrue(cache_mgr.inspect_and_update(fake_hits_2))


class TestAlertSyncEngine(unittest.TestCase):
    @patch("services.opensearch_client.get_latest_alerts", return_value=[
        {"_id": "doc1", "_source": {"@timestamp": "2026-08-06T11:30:00.000Z"}}
    ])
    def test_fetch_fresh_alerts(self, mock_alerts):
        engine = AlertSyncEngine()
        alerts = engine.fetch_fresh_alerts(size=10)
        self.assertEqual(len(alerts), 1)
        summary = engine.get_latest_telemetry_summary()
        self.assertIn("opensearch_connected", summary)
        self.assertIn("wazuh_api_connected", summary)


class TestTelemetryRecoveryEngine(unittest.TestCase):
    @patch("telemetry.connection_manager.TelemetryConnectionManager.reconnect_opensearch_client", return_value=True)
    def test_telemetry_recovery_execution(self, mock_reconnect):
        recovery = TelemetryRecoveryEngine()
        res = recovery.execute_telemetry_recovery(reason="Test Trigger")
        self.assertIn("success", res)
        self.assertTrue(res["success"])


class TestBackgroundAlertMonitor(unittest.TestCase):
    def test_monitor_lifecycle(self):
        monitor = BackgroundAlertMonitor(check_interval=1)
        monitor.start()
        self.assertTrue(monitor.running)
        monitor.stop()
        self.assertFalse(monitor.running)


if __name__ == "__main__":
    unittest.main()
