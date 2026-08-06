import os
import unittest
import tempfile
import shutil
from unittest.mock import patch, MagicMock

from runtime.logger import SensitiveDataFilter, log_runtime_event, get_runtime_logger
from runtime.privileged_executor import PrivilegedExecutor, get_privileged_executor
from runtime.connection_monitor import ConnectionMonitor, ConnectionState
from runtime.wazuh_health import WazuhHealthMonitor
from runtime.recovery_manager import RuntimeRecoveryManager
from runtime.watchdog import RuntimeWatchdog, start_runtime_watchdog


class TestRuntimeLogger(unittest.TestCase):
    def test_sensitive_data_filter(self):
        filt = SensitiveDataFilter()
        record = MagicMock()
        record.msg = "Connecting with password='supersecretpass123' and token='abc123xyz'"
        filt.filter(record)
        self.assertNotIn("supersecretpass123", record.msg)
        self.assertNotIn("abc123xyz", record.msg)
        self.assertIn("[REDACTED]", record.msg)

    def test_log_runtime_event(self):
        # Should execute without throwing exception
        log_runtime_event(
            event_type="TEST_EVENT",
            connection_lost=False,
            recovery_started=True,
            recovery_successful=True,
            reason="Unit Test Execution"
        )


class TestPrivilegedExecutor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("test_content_123")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_file_exists_and_read(self):
        executor = get_privileged_executor()
        self.assertTrue(executor.file_exists_safe(self.test_file))
        content = executor.read_file_safe(self.test_file)
        self.assertEqual(content, "test_content_123")

    def test_write_file_safe(self):
        executor = get_privileged_executor()
        out_file = os.path.join(self.temp_dir, "out.txt")
        written = executor.write_file_safe(out_file, "new_output_data")
        self.assertTrue(written)
        self.assertEqual(executor.read_file_safe(out_file), "new_output_data")


class TestConnectionMonitor(unittest.TestCase):
    def test_connection_state_evaluation(self):
        monitor = ConnectionMonitor()
        eval_res = monitor.evaluate_connection_state()
        self.assertIn("state", eval_res)
        self.assertIn("reason", eval_res)
        self.assertIn(eval_res["state"], [
            ConnectionState.HEALTHY,
            ConnectionState.NETWORK_LOST,
            ConnectionState.LAPTOP_SLEEP,
            ConnectionState.IP_CHANGE,
            ConnectionState.MANAGER_RESTART,
            ConnectionState.INDEXER_RESTART,
            ConnectionState.AUTH_FAILURE,
            ConnectionState.ENROLLMENT_FAILURE,
            ConnectionState.PACKET_LOSS,
            ConnectionState.AGENT_DISCONNECTED
        ])


class TestWazuhHealthMonitor(unittest.TestCase):
    def test_wazuh_health_inspection(self):
        health_mon = WazuhHealthMonitor()
        res = health_mon.check_wazuh_health()
        self.assertIn("healthy", res)
        self.assertIn("status", res)
        self.assertIn("agent_process_running", res)
        self.assertIn("client_keys_valid", res)


class TestRuntimeRecoveryManager(unittest.TestCase):
    @patch("runtime.privileged_executor.PrivilegedExecutor.restart_service_safe", return_value=True)
    def test_targeted_recovery_execution(self, mock_restart):
        recovery_mgr = RuntimeRecoveryManager()
        info = {
            "state": ConnectionState.AGENT_DISCONNECTED,
            "reason": "Agent process stopped",
            "ip": "127.0.0.1"
        }
        res = recovery_mgr.execute_targeted_recovery(info)
        self.assertIn("success", res)
        self.assertIn("consecutive_failures", res)


class TestRuntimeWatchdog(unittest.TestCase):
    def test_watchdog_lifecycle(self):
        watchdog = RuntimeWatchdog(check_interval=1)
        watchdog.start()
        self.assertTrue(watchdog.running)
        watchdog.stop()
        self.assertFalse(watchdog.running)


if __name__ == "__main__":
    unittest.main()
