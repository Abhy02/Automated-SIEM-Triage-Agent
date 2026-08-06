import urllib.request
import urllib.parse
import ssl
import socket
from config import Config
from .logger import get_telemetry_logger, log_telemetry_event

logger = get_telemetry_logger()


class TelemetryConnectionManager:
    """
    Manages OpenSearch and Wazuh API connection health and re-instantiation.
    Ensures telemetry clients never remain stale when network or Docker reconnects.
    """

    def __init__(self):
        self.opensearch_healthy = False
        self.wazuh_api_healthy = False

    def _create_unverified_context(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def verify_opensearch(self) -> bool:
        """Verify OpenSearch 127.0.0.1:9200 connection status."""
        urls = ["https://127.0.0.1:9200", "http://127.0.0.1:9200"]
        if Config.OPENSEARCH_HOST and Config.OPENSEARCH_HOST not in urls:
            urls.append(Config.OPENSEARCH_HOST)

        ctx = self._create_unverified_context()
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "AISOC-TelemetryConnManager"})
                with urllib.request.urlopen(req, context=ctx, timeout=3) as resp:
                    if resp.status in (200, 401, 403):
                        self.opensearch_healthy = True
                        return True
            except urllib.error.HTTPError as e:
                if e.code in (200, 401, 403):
                    self.opensearch_healthy = True
                    return True
            except Exception:
                pass

        try:
            with socket.create_connection(("127.0.0.1", 9200), timeout=2):
                self.opensearch_healthy = True
                return True
        except Exception:
            pass

        self.opensearch_healthy = False
        return False

    def verify_wazuh_api(self) -> bool:
        """Verify Wazuh API 127.0.0.1:55000 connection status."""
        urls = ["https://127.0.0.1:55000", "http://127.0.0.1:55000"]
        if Config.WAZUH_HOST and Config.WAZUH_HOST not in urls:
            urls.append(Config.WAZUH_HOST)

        ctx = self._create_unverified_context()
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "AISOC-TelemetryConnManager"})
                with urllib.request.urlopen(req, context=ctx, timeout=3) as resp:
                    self.wazuh_api_healthy = True
                    return True
            except urllib.error.HTTPError as e:
                if e.code in (200, 401, 403):
                    self.wazuh_api_healthy = True
                    return True
            except Exception:
                pass

        try:
            with socket.create_connection(("127.0.0.1", 55000), timeout=2):
                self.wazuh_api_healthy = True
                return True
        except Exception:
            pass

        self.wazuh_api_healthy = False
        return False

    def reconnect_opensearch_client(self):
        """
        Re-initializes in-memory OpenSearch client connection.
        """
        try:
            from services.opensearch_client import refresh_opensearch_client
            client = refresh_opensearch_client()
            if client is not None:
                logger.info("OpenSearch client re-initialized successfully.")
                log_telemetry_event(
                    event_type="OPENSEARCH_RECONNECTED",
                    opensearch_connected=True,
                    message="OpenSearch client recreated successfully"
                )
                return True
        except Exception as e:
            logger.error(f"Failed to re-initialize OpenSearch client: {e}")
        return False

    def reconnect_wazuh_api(self):
        """
        Refreshes Wazuh API authentication token and connection.
        """
        try:
            from services.wazuh_api import get_token
            token = get_token()
            if token:
                logger.info("Wazuh API token & connection re-authenticated successfully.")
                log_telemetry_event(
                    event_type="WAZUH_API_RECONNECTED",
                    wazuh_api_connected=True,
                    message="Wazuh API re-authenticated successfully"
                )
                return True
        except Exception as e:
            logger.warning(f"Wazuh API re-authentication notice: {e}")
        return False
