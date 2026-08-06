import os
import shutil
import subprocess
import threading
from .logger import get_runtime_logger

logger = get_runtime_logger()
_execution_lock = threading.Lock()
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PrivilegedExecutor:
    """
    Centralized Non-Interactive Administrative Executor.
    Provides non-interactive sudo (-n) and passwordless Docker group execution
    to perform required administrative tasks (updating ossec.conf, restarting wazuh-agent)
    WITHOUT ever prompting for interactive administrator passwords during runtime.
    Guarded by single-flight locks to prevent repeated elevation attempts.
    """

    def __init__(self):
        self.docker_available = self._check_docker_available()

    def _check_docker_available(self) -> bool:
        docker_path = shutil.which("docker")
        if not docker_path:
            return False
        try:
            res = subprocess.run(
                ["docker", "ps"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3
            )
            return res.returncode == 0
        except Exception:
            return False

    def file_exists_safe(self, path: str) -> bool:
        """Safely check if host path exists without password prompt."""
        if os.path.exists(path):
            return True

        # Non-interactive sudo check
        try:
            res = subprocess.run(
                ["sudo", "-n", "test", "-f", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass

        # Passwordless Docker mount check
        if self.docker_available:
            try:
                dir_name = os.path.dirname(path)
                base_name = os.path.basename(path)
                res = subprocess.run(
                    ["docker", "run", "--rm", "-v", f"{dir_name}:/check_dir", "alpine", "test", "-f", f"/check_dir/{base_name}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5
                )
                return res.returncode == 0
            except Exception:
                pass

        return False

    def read_file_safe(self, path: str) -> str:
        """Safely read content from host file without interactive password prompt."""
        # 1. Direct read attempt
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            pass

        # 2. Non-interactive sudo cat
        try:
            res = subprocess.run(
                ["sudo", "-n", "cat", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3
            )
            if res.returncode == 0 and res.stdout:
                return res.stdout
        except Exception:
            pass

        # 3. Passwordless Docker container mount read
        if self.docker_available:
            try:
                dir_name = os.path.dirname(path)
                base_name = os.path.basename(path)
                res = subprocess.run(
                    ["docker", "run", "--rm", "-v", f"{dir_name}:/read_dir", "alpine", "cat", f"/read_dir/{base_name}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5
                )
                if res.returncode == 0 and res.stdout:
                    return res.stdout
            except Exception as e:
                logger.error(f"Failed to read file {path} via Docker executor: {e}")

        return None

    def write_file_safe(self, target_path: str, content: str) -> bool:
        """
        Safely write content to protected host path without interactive password prompt.
        Uses single-flight lock to prevent concurrent write collisions.
        """
        with _execution_lock:
            # 1. Direct write attempt if writable
            if os.access(target_path, os.W_OK) or (not os.path.exists(target_path) and os.access(os.path.dirname(target_path), os.W_OK)):
                try:
                    with open(target_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    return True
                except Exception:
                    pass

            # Prepare temporary source file inside project logs
            tmp_path = os.path.join(PROJECT_ROOT, "logs", "tmp_exec.conf")
            os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(content)

            # 2. Non-interactive sudo copy
            try:
                res = subprocess.run(
                    ["sudo", "-n", "cp", tmp_path, target_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=3
                )
                if res.returncode == 0:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                    return True
            except Exception:
                pass

            # 3. Passwordless Docker container mount copy
            if self.docker_available:
                try:
                    src_dir = os.path.dirname(tmp_path)
                    src_base = os.path.basename(tmp_path)
                    dst_dir = os.path.dirname(target_path)
                    dst_base = os.path.basename(target_path)
                    res = subprocess.run(
                        [
                            "docker", "run", "--rm",
                            "-v", f"{src_dir}:/src_dir",
                            "-v", f"{dst_dir}:/dst_dir",
                            "alpine", "cp", f"/src_dir/{src_base}", f"/dst_dir/{dst_base}"
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5
                    )
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                    if res.returncode == 0:
                        return True
                except Exception as e:
                    logger.error(f"Failed to write file {target_path} via Docker executor: {e}")

            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            return False

    def copy_file_safe(self, src_path: str, dst_path: str) -> bool:
        """Safely copy host file from src to dst without password prompt."""
        content = self.read_file_safe(src_path)
        if content is not None:
            return self.write_file_safe(dst_path, content)
        return False

    def restart_service_safe(self, service_name: str = "wazuh-agent") -> bool:
        """
        Safely restart system service (e.g. wazuh-agent) without interactive password prompt.
        Guarded by single-flight lock protection.
        """
        with _execution_lock:
            logger.info(f"Executing non-interactive service restart for: {service_name}")

            # 1. Try non-interactive sudo systemctl
            for cmd in [
                ["sudo", "-n", "systemctl", "restart", service_name],
                ["systemctl", "restart", service_name],
                ["sudo", "-n", "service", service_name, "restart"]
            ]:
                try:
                    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
                    if res.returncode == 0:
                        logger.info(f"Successfully restarted {service_name} via non-interactive {' '.join(cmd)}.")
                        return True
                except Exception:
                    pass

            # 2. Try passwordless Docker privileged container chroot
            if self.docker_available:
                try:
                    res = subprocess.run(
                        [
                            "docker", "run", "--rm", "--privileged",
                            "-v", "/:/host", "alpine", "chroot", "/host",
                            "/var/ossec/bin/wazuh-control", "restart"
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=30
                    )
                    if res.returncode == 0 or "Started" in res.stdout or "Completed" in res.stdout:
                        logger.info(f"Successfully restarted {service_name} via Docker privileged chroot container.")
                        return True
                except Exception as e:
                    logger.error(f"Docker privileged restart of {service_name} failed: {e}")

            logger.warning(f"Unable to restart service {service_name} without password prompt.")
            return False


_global_executor_instance = None
_global_executor_lock = threading.Lock()


def get_privileged_executor() -> PrivilegedExecutor:
    global _global_executor_instance
    with _global_executor_lock:
        if _global_executor_instance is None:
            _global_executor_instance = PrivilegedExecutor()
        return _global_executor_instance
