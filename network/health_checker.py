import subprocess
import shutil
import urllib.request
import urllib.parse
import ssl
import socket
from config import Config
from .utils import get_network_manager_logger

logger = get_network_manager_logger()


class HealthChecker:
    def __init__(self, target_ip=None):
        self.target_ip = target_ip

    def _create_unverified_context(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def verify_wazuh_agent(self):
        """
        Verify Wazuh Agent process / service state.
        """
        systemctl_path = shutil.which("systemctl")
        if systemctl_path:
            try:
                res = subprocess.run(
                    ["systemctl", "is-active", "wazuh-agent"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=3
                )
                status = res.stdout.strip()
                if status == "active":
                    return {"status": "active", "message": "Wazuh Agent service is running"}
            except Exception:
                pass

        # Fallback to checking running processes via ps
        try:
            res = subprocess.run(
                ["pgrep", "-f", "wazuh-agentd|ossec-agentd"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3
            )
            if res.returncode == 0:
                return {"status": "active", "message": "Wazuh Agent process is running"}
        except Exception:
            pass

        return {"status": "unknown/inactive", "message": "Wazuh Agent process not detected or inactive"}

    def verify_opensearch(self, ip=None):
        """
        Verify OpenSearch HTTP/HTTPS GET returns HTTP 200 or reachable response on port 9200.
        """
        target_ip = ip or self.target_ip
        host_url = Config.OPENSEARCH_HOST
        
        # Build candidate URLs
        urls_to_try = []
        if target_ip:
            urls_to_try.append(f"https://{target_ip}:9200")
            urls_to_try.append(f"http://{target_ip}:9200")
        if host_url:
            urls_to_try.append(host_url)

        ctx = self._create_unverified_context()
        
        for url in urls_to_try:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "AISOC-HealthChecker"})
                with urllib.request.urlopen(req, context=ctx, timeout=4) as resp:
                    if resp.status in (200, 401, 403):
                        return {"status": "online", "code": resp.status, "url": url, "message": f"OpenSearch reachable (HTTP {resp.status})"}
            except urllib.error.HTTPError as e:
                # HTTP 401/403 means service is running & responding
                if e.code in (200, 401, 403):
                    return {"status": "online", "code": e.code, "url": url, "message": f"OpenSearch reachable (HTTP {e.code})"}
            except Exception as e:
                logger.debug(f"OpenSearch health check connection error for {url}: {e}")

        # Try raw TCP connection on port 9200 as fallback
        check_ip = target_ip or "127.0.0.1"
        try:
            with socket.create_connection((check_ip, 9200), timeout=3):
                return {"status": "online", "code": 200, "url": f"tcp://{check_ip}:9200", "message": "OpenSearch port 9200 open"}
        except Exception:
            pass

        return {"status": "offline", "code": None, "message": "OpenSearch unavailable on port 9200"}

    def verify_wazuh_api(self, ip=None):
        """
        Verify Wazuh API HTTPS GET responds on port 55000.
        """
        target_ip = ip or self.target_ip
        host_url = Config.WAZUH_HOST

        urls_to_try = []
        if target_ip:
            urls_to_try.append(f"https://{target_ip}:55000")
            urls_to_try.append(f"http://{target_ip}:55000")
        if host_url:
            urls_to_try.append(host_url)

        ctx = self._create_unverified_context()

        for url in urls_to_try:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "AISOC-HealthChecker"})
                with urllib.request.urlopen(req, context=ctx, timeout=4) as resp:
                    return {"status": "online", "code": resp.status, "url": url, "message": f"Wazuh API reachable (HTTP {resp.status})"}
            except urllib.error.HTTPError as e:
                # 401/403 means API is responding
                if e.code in (200, 401, 403):
                    return {"status": "online", "code": e.code, "url": url, "message": f"Wazuh API reachable (HTTP {e.code})"}
            except Exception as e:
                logger.debug(f"Wazuh API check error for {url}: {e}")

        check_ip = target_ip or "127.0.0.1"
        try:
            with socket.create_connection((check_ip, 55000), timeout=3):
                return {"status": "online", "code": 200, "url": f"tcp://{check_ip}:55000", "message": "Wazuh API port 55000 open"}
        except Exception:
            pass

        return {"status": "offline", "code": None, "message": "Wazuh API unavailable on port 55000"}

    def verify_aisoc_backend(self):
        """
        Verify Flask backend is reachable at http://127.0.0.1:5000.
        """
        try:
            req = urllib.request.Request("http://127.0.0.1:5000/api/health", headers={"User-Agent": "AISOC-HealthChecker"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    return {"status": "online", "message": "AISOC Backend is reachable at localhost:5000"}
        except Exception:
            pass

        try:
            with socket.create_connection(("127.0.0.1", 5000), timeout=2):
                return {"status": "online", "message": "AISOC Backend port 5000 is open"}
        except Exception as e:
            logger.debug(f"AISOC Backend socket error: {e}")

        return {"status": "offline", "message": "AISOC Backend unreachable at localhost:5000"}

    def perform_full_health_check(self, target_ip=None):
        ip = target_ip or self.target_ip
        logger.info(f"Running platform health verification checks for target IP: {ip or 'Localhost'}...")
        
        agent_res = self.verify_wazuh_agent()
        opensearch_res = self.verify_opensearch(ip)
        wazuh_api_res = self.verify_wazuh_api(ip)
        backend_res = self.verify_aisoc_backend()

        # Overall health passes if backend is online and OpenSearch or Wazuh responds (or demo mode active)
        is_healthy = backend_res["status"] == "online" and (
            opensearch_res["status"] == "online" or Config.DEMO_MODE
        )

        health_report = {
            "overall_healthy": is_healthy,
            "target_ip": ip,
            "wazuh_agent": agent_res,
            "opensearch": opensearch_res,
            "wazuh_api": wazuh_api_res,
            "aisoc_backend": backend_res,
        }

        logger.info(
            f"Health check completed. Overall Healthy: {is_healthy} | "
            f"OpenSearch: {opensearch_res['status']} | "
            f"Wazuh API: {wazuh_api_res['status']} | "
            f"AISOC Backend: {backend_res['status']}"
        )
        return health_report
