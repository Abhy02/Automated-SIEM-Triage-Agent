import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from config import Config
from .utils import get_network_manager_logger

logger = get_network_manager_logger()

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(PROJECT_ROOT, ".env")
ENV_BAK_FILE = os.path.join(PROJECT_ROOT, ".env.bak")
OSSEC_CONF_FILE = "/var/ossec/etc/ossec.conf"
OSSEC_CONF_BAK_FILE = os.path.join(PROJECT_ROOT, "logs", "ossec.conf.bak")


from runtime.privileged_executor import get_privileged_executor

class ConfigurationUpdater:
    def __init__(self, env_path=ENV_FILE, ossec_path=OSSEC_CONF_FILE):
        self.env_path = env_path
        self.env_bak_path = ENV_BAK_FILE
        self.ossec_path = ossec_path
        self.ossec_bak_path = OSSEC_CONF_BAK_FILE
        self.backups_created = []
        self.executor = get_privileged_executor()



    def rollback(self):
        """
        Restore original configuration files from backups if an update or health check fails.
        """
        logger.warning("Initiating configuration rollback to previous working state...")
        success = True
        for original, backup in self.backups_created:
            if os.path.exists(backup):
                try:
                    if original == self.ossec_path and not os.access(self.ossec_path, os.W_OK):
                        subprocess.run(
                            ["sudo", "cp", backup, original],
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        )
                    else:
                        shutil.copy2(backup, original)
                    logger.info(f"Restored configuration file: {original} from {backup}")
                except Exception as e:
                    logger.error(f"Failed to restore {original} from {backup}: {e}")
                    success = False

        # Reload environment and Config state back to restored values
        if os.path.exists(self.env_path):
            self._update_runtime_env()

        return success

    def _replace_ip_in_url(self, url_val, new_ip):
        """
        Replaces IPv4 or hostname in URL while preserving protocol scheme and port number.
        Example: https://192.168.1.14:9200 -> https://<NEW_IP>:9200
        """
        if not url_val or not isinstance(url_val, str):
            return url_val
        
        pattern = r"^(https?://)([0-9a-zA-Z\.\-]+)(:[0-9]+)?(.*)$"
        match = re.match(pattern, url_val.strip())
        if match:
            scheme = match.group(1)
            port = match.group(3) or ""
            path = match.group(4) or ""
            return f"{scheme}{new_ip}{port}{path}"
        return url_val

    def update_env_file(self, new_ip):
        """
        Updates network-related variables in .env file (WAZUH_HOST, INDEXER_HOST, OPENSEARCH_HOST).
        Leaves all other environment variables untouched.
        """
        if not os.path.exists(self.env_path):
            logger.warning(f".env file not found at {self.env_path}, skipping .env file write.")
            return False

        target_keys = {"WAZUH_HOST", "INDEXER_HOST", "OPENSEARCH_HOST", "WAZUH_API_URL"}
        updated_lines = []
        modified = False

        with open(self.env_path, "r") as f:
            lines = f.readlines()

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                updated_lines.append(line)
                continue

            if "=" in line:
                key, val = line.split("=", 1)
                key_clean = key.strip()
                val_clean = val.strip().strip("'\"")

                if key_clean in target_keys:
                    new_val = self._replace_ip_in_url(val_clean, new_ip)
                    if new_val != val_clean:
                        line = f"{key_clean}={new_val}\n"
                        modified = True
                        logger.info(f"Updating .env setting {key_clean}: {val_clean} -> {new_val}")
            
            updated_lines.append(line)

        if modified:
            with open(self.env_path, "w") as f:
                f.writelines(updated_lines)
            logger.info("Successfully updated .env file with new IP.")
        else:
            logger.info(".env file already contains updated IP configuration.")

        return True

    def _file_exists_safe(self, path):
        return self.executor.file_exists_safe(path)

    def _read_file_safe(self, path):
        return self.executor.read_file_safe(path)

    def create_backups(self):
        """
        Create backup copies of .env and ossec.conf prior to making any modifications.
        """
        self.backups_created = []
        
        # 1. Backup .env
        if os.path.exists(self.env_path):
            try:
                shutil.copy2(self.env_path, self.env_bak_path)
                self.backups_created.append((self.env_path, self.env_bak_path))
                logger.info(f"Created backup: {self.env_bak_path}")
            except Exception as e:
                logger.error(f"Failed to create backup for {self.env_path}: {e}")
                raise

        # 2. Backup ossec.conf
        if self._file_exists_safe(self.ossec_path):
            try:
                os.makedirs(os.path.dirname(self.ossec_bak_path), exist_ok=True)
                copied = self.executor.copy_file_safe(self.ossec_path, self.ossec_bak_path)
                if copied:
                    self.backups_created.append((self.ossec_path, self.ossec_bak_path))
                    logger.info(f"Created backup: {self.ossec_bak_path}")
            except Exception as e:
                logger.warning(f"Unable to backup {self.ossec_path}: {e}")

    def update_ossec_conf(self, new_ip):
        """
        Updates <server><address> inside /var/ossec/etc/ossec.conf if it exists.
        Only modifies the address tag, keeping all other XML tags intact.
        """
        if not self._file_exists_safe(self.ossec_path):
            logger.info(f"{self.ossec_path} does not exist on this host, skipping Wazuh Agent XML update.")
            return True

        try:
            content = self._read_file_safe(self.ossec_path)
            if not content:
                logger.warning(f"Unable to read content from {self.ossec_path}")
                return False

            # 1. Regex replacement inside <server><address>...</address></server>
            pattern = r"(<server\b[^>]*>.*?<address>)([^<]+)(</address>.*?</server>)"
            
            def replace_address(m):
                prefix, old_addr, suffix = m.groups()
                if old_addr.strip() != new_ip:
                    logger.info(f"Updating ossec.conf server address: {old_addr.strip()} -> {new_ip}")
                    return f"{prefix}{new_ip}{suffix}"
                return m.group(0)

            new_content, count = re.subn(pattern, replace_address, content, flags=re.DOTALL)

            # 2. Disable auto-enrollment retry if client keys already exist to prevent looping on old IP
            if "<enrollment>" in new_content:
                new_content = re.sub(
                    r"(<enrollment\b[^>]*>.*?<enabled>)(yes)(</enabled>)",
                    r"\g<1>no\g<3>",
                    new_content,
                    flags=re.DOTALL
                )

            # 3. Ensure auth.log localfile is present for SSH & login telemetry
            if "/var/log/auth.log" not in new_content:
                auth_block = (
                    "  <localfile>\n"
                    "    <log_format>syslog</log_format>\n"
                    "    <location>/var/log/auth.log</location>\n"
                    "  </localfile>\n\n"
                    "</ossec_config>"
                )
                new_content = re.sub(r"</ossec_config>", auth_block, new_content, count=1)
            
            if new_content != content:
                written = self.executor.write_file_safe(self.ossec_path, new_content)
                if written:
                    logger.info("Successfully updated /var/ossec/etc/ossec.conf")
                else:
                    logger.error("Failed to write updated content to /var/ossec/etc/ossec.conf")
                    return False
            else:
                logger.info("/var/ossec/etc/ossec.conf server address is already up to date.")

            return True
        except Exception as e:
            logger.error(f"Failed to update /var/ossec/etc/ossec.conf: {e}")
            return False

    def _update_runtime_env(self):
        """
        Reload updated environment variables into os.environ and Config class in memory.
        """
        if os.path.exists(self.env_path):
            with open(self.env_path, "r") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#") and "=" in stripped:
                        key, val = stripped.split("=", 1)
                        os.environ[key.strip()] = val.strip().strip("'\"")

        # Update Flask Config attributes
        if "WAZUH_HOST" in os.environ:
            Config.WAZUH_HOST = os.environ["WAZUH_HOST"]
        if "OPENSEARCH_HOST" in os.environ:
            Config.OPENSEARCH_HOST = os.environ["OPENSEARCH_HOST"]
        elif "INDEXER_HOST" in os.environ:
            Config.OPENSEARCH_HOST = os.environ["INDEXER_HOST"]

        # Dynamically refresh in-memory service clients
        try:
            from services.opensearch_client import refresh_opensearch_client
            refresh_opensearch_client()
        except Exception:
            pass

    def apply_ip_update(self, new_ip="127.0.0.1"):
        """
        Applies configuration updates with backup & rollback safety.
        Defaults to static localhost 127.0.0.1 architecture.
        """
        target_ip = new_ip or "127.0.0.1"
        logger.info(f"Applying configuration update for static target IP: {target_ip}")
        try:
            self.create_backups()
            self.update_env_file(target_ip)
            # For ossec.conf, if target is 127.0.0.1, set container IP or 127.0.0.1
            ossec_ip = "172.19.0.3" if target_ip in ("127.0.0.1", "localhost") else target_ip
            self.update_ossec_conf(ossec_ip)
            self._update_runtime_env()
            return True
        except Exception as e:
            logger.error(f"Error during configuration update: {e}. Restoring backup...")
            self.rollback()
            return False
