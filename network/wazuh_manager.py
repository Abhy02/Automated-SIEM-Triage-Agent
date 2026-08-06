import subprocess
import shutil
from .utils import get_network_manager_logger

logger = get_network_manager_logger()


class WazuhManager:
    """
    Manages Wazuh Agent system service and single-node Wazuh Docker container restarts.
    Ensures intelligent restarts only when services are present and active.
    """

    def is_wazuh_agent_installed(self):
        systemctl_path = shutil.which("systemctl")
        if not systemctl_path:
            return False
        try:
            res = subprocess.run(
                ["systemctl", "status", "wazuh-agent"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3
            )
            # returncode 0 = active, 3 = inactive, 4 = unit not found
            return res.returncode in (0, 3)
        except Exception:
            return False

    def restart_wazuh_agent(self):
        if not self.is_wazuh_agent_installed():
            logger.info("wazuh-agent service not found or inactive. Skipping systemctl restart.")
            return False

        logger.info("Attempting to restart wazuh-agent service...")
        try:
            res = subprocess.run(
                ["sudo", "systemctl", "restart", "wazuh-agent"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15
            )
            if res.returncode == 0:
                logger.info("Successfully restarted wazuh-agent service.")
                return True
            else:
                # Try without sudo as fallback if already root
                res2 = subprocess.run(
                    ["systemctl", "restart", "wazuh-agent"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=15
                )
                if res2.returncode == 0:
                    logger.info("Successfully restarted wazuh-agent service.")
                    return True
                logger.warning(f"Failed to restart wazuh-agent: {res.stderr or res2.stderr}")
        except Exception as e:
            logger.error(f"Exception restarting wazuh-agent: {e}")
        return False

    def get_wazuh_docker_containers(self):
        """
        Detect running Wazuh or OpenSearch docker containers.
        """
        docker_path = shutil.which("docker")
        if not docker_path:
            return []

        try:
            res = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            if res.returncode == 0:
                container_names = res.stdout.strip().splitlines()
                wazuh_containers = [
                    c for c in container_names 
                    if any(term in c.lower() for term in ("wazuh", "opensearch", "indexer", "manager"))
                ]
                return wazuh_containers
        except Exception as e:
            logger.debug(f"Docker ps check exception: {e}")
        return []

    def restart_wazuh_containers(self):
        containers = self.get_wazuh_docker_containers()
        restarted = []
        if not containers:
            logger.info("No active Wazuh/OpenSearch Docker containers detected.")
            return restarted

        for container in containers:
            logger.info(f"Restarting Docker container: {container}")
            try:
                res = subprocess.run(
                    ["docker", "restart", container],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30
                )
                if res.returncode == 0:
                    logger.info(f"Successfully restarted container: {container}")
                    restarted.append(container)
                else:
                    logger.warning(f"Failed to restart container {container}: {res.stderr}")
            except Exception as e:
                logger.error(f"Error restarting docker container {container}: {e}")

        return restarted

    def restart_required_services(self):
        """
        Intelligently restarts only required active services (Wazuh Agent and/or Docker containers).
        Returns list of restarted service names.
        """
        restarted_services = []

        if self.restart_wazuh_agent():
            restarted_services.append("wazuh-agent")

        containers = self.restart_wazuh_containers()
        restarted_services.extend(containers)

        return restarted_services
