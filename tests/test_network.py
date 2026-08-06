import os
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from network.ip_detector import is_valid_lan_ipv4, get_active_lan_ip, get_active_network_details
from network.config_updater import ConfigurationUpdater
from network.wazuh_recovery import WazuhRecoveryManager, WazuhManager
from network.health_checker import HealthChecker
from network.startup_validator import StartupValidator
from network.network_monitor import NetworkMonitor
from network.logger import SensitiveDataFilter, log_recovery_event
from network.utils import load_network_state, save_network_state


class TestIPDetector(unittest.TestCase):
    def test_is_valid_lan_ipv4(self):
        self.assertTrue(is_valid_lan_ipv4("192.168.1.100"))
        self.assertTrue(is_valid_lan_ipv4("10.0.0.5"))
        self.assertTrue(is_valid_lan_ipv4("172.16.0.1"))
        
        self.assertFalse(is_valid_lan_ipv4("127.0.0.1"))
        self.assertFalse(is_valid_lan_ipv4("169.254.1.1"))
        self.assertFalse(is_valid_lan_ipv4("224.0.0.1"))
        self.assertFalse(is_valid_lan_ipv4("0.0.0.0"))
        self.assertFalse(is_valid_lan_ipv4("invalid_ip"))
        self.assertFalse(is_valid_lan_ipv4(None))

    def test_get_active_lan_ip(self):
        ip = get_active_lan_ip()
        if ip:
            self.assertTrue(is_valid_lan_ipv4(ip))

    def test_get_active_network_details(self):
        details = get_active_network_details()
        self.assertIn("ip", details)
        self.assertIn("gateway", details)
        self.assertIn("interface", details)


class TestConfigUpdater(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_env = os.path.join(self.temp_dir, ".env")
        self.temp_ossec = os.path.join(self.temp_dir, "ossec.conf")

        with open(self.temp_env, "w") as f:
            f.write(
                "SECRET_KEY=aisoc-secret-key-123\n"
                "WAZUH_HOST=https://192.168.1.10:55000\n"
                "INDEXER_HOST=https://192.168.1.10:9200\n"
                "VT_API_KEY=supersecretkey123\n"
            )

        with open(self.temp_ossec, "w") as f:
            f.write(
                "<ossec_config>\n"
                "  <client>\n"
                "    <server>\n"
                "      <address>192.168.1.10</address>\n"
                "      <port>1514</port>\n"
                "    </server>\n"
                "  </client>\n"
                "</ossec_config>\n"
            )

        self.updater = ConfigurationUpdater(env_path=self.temp_env, ossec_path=self.temp_ossec)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_env_update_and_rollback(self):
        new_ip = "192.168.1.200"
        
        # Test update
        success = self.updater.apply_ip_update(new_ip)
        self.assertTrue(success)

        with open(self.temp_env, "r") as f:
            content = f.read()
        self.assertIn(f"WAZUH_HOST=https://{new_ip}:55000", content)
        self.assertIn(f"INDEXER_HOST=https://{new_ip}:9200", content)
        self.assertIn("VT_API_KEY=supersecretkey123", content)

        # Test ossec update
        with open(self.temp_ossec, "r") as f:
            xml_content = f.read()
        self.assertIn(f"<address>{new_ip}</address>", xml_content)

        # Test rollback
        rollback_ok = self.updater.rollback()
        self.assertTrue(rollback_ok)

        with open(self.temp_env, "r") as f:
            restored_content = f.read()
        self.assertIn("WAZUH_HOST=https://192.168.1.10:55000", restored_content)


class TestWazuhRecoveryManager(unittest.TestCase):
    @patch("network.wazuh_recovery.WazuhRecoveryManager.restart_wazuh_agent", return_value=True)
    def test_wazuh_recovery_manager_methods(self, mock_restart):
        mgr = WazuhRecoveryManager()
        status = mgr.get_agent_status()
        self.assertIn(status, ["active", "inactive", "disconnected", "not_installed", "unknown"])
        self.assertIsInstance(mgr.has_valid_client_keys(), bool)


class TestStartupValidator(unittest.TestCase):
    @patch("network.wazuh_recovery.WazuhRecoveryManager.restart_wazuh_agent", return_value=True)
    def test_startup_validator_execution(self, mock_restart):
        validator = StartupValidator()
        res = validator.validate_and_synchronize_on_startup()
        self.assertIn("success", res)
        self.assertIn("health", res)


class TestHealthChecker(unittest.TestCase):
    def test_health_checks_structure(self):
        checker = HealthChecker(target_ip="127.0.0.1")
        rpt = checker.perform_full_health_check("127.0.0.1")
        
        self.assertIn("overall_healthy", rpt)
        self.assertIn("wazuh_agent", rpt)
        self.assertIn("opensearch", rpt)
        self.assertIn("wazuh_api", rpt)
        self.assertIn("aisoc_backend", rpt)


class TestSensitiveDataFilter(unittest.TestCase):
    def test_sensitive_logging_redaction(self):
        filtr = SensitiveDataFilter()
        record = MagicMock()
        record.msg = "Connecting with password='SuperSecretPassword123' and api_key='KeyXYZ'"
        
        filtr.filter(record)
        self.assertNotIn("SuperSecretPassword123", record.msg)
        self.assertIn("[REDACTED]", record.msg)


if __name__ == "__main__":
    unittest.main()
