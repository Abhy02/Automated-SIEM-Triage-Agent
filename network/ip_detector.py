import os
import socket
import subprocess
import re
from .utils import get_network_manager_logger

logger = get_network_manager_logger()

# Interface prefixes to allow (standard physical LAN/WLAN interfaces)
ALLOWED_INTERFACE_PREFIXES = ("wlan", "eth", "en", "wlp", "eno", "ens", "wl", "ww")

# Interface prefixes to strictly ignore
IGNORED_INTERFACE_PREFIXES = ("lo", "docker", "veth", "br-", "vbox", "virbr", "tun", "tap", "zt", "tailscale", "flannel", "cni")


def is_valid_lan_ipv4(ip_str):
    """
    Check if an IPv4 address is a valid non-loopback, non-link-local, non-multicast LAN address.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    
    # Simple regex check for IPv4 syntax
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False

    # Check valid byte range
    if any(o < 0 or o > 255 for o in octets):
        return False

    # Filter loopback (127.x.x.x)
    if octets[0] == 127:
        return False

    # Filter link-local (169.254.x.x)
    if octets[0] == 169 and octets[1] == 254:
        return False

    # Filter multicast / reserved (224.0.0.0+)
    if octets[0] >= 224:
        return False

    # Filter 0.0.0.0
    if ip_str == "0.0.0.0":
        return False

    return True


def get_interface_from_route():
    """
    Attempt to find the active outbound LAN IP using UDP socket connection attempt.
    This does not send actual packets over the wire, but queries system routing table.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to a public IP to determine default gateway interface IP
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        if is_valid_lan_ipv4(ip):
            return ip
    except Exception:
        pass
    finally:
        s.close()
    return None


def get_interfaces_via_sysfs():
    """
    Enumerate physical interfaces using /sys/class/net on Linux systems.
    """
    interfaces = []
    sys_net = "/sys/class/net"
    if os.path.exists(sys_net):
        try:
            for iface in os.listdir(sys_net):
                if iface.startswith(IGNORED_INTERFACE_PREFIXES):
                    continue
                if iface.startswith(ALLOWED_INTERFACE_PREFIXES):
                    interfaces.append(iface)
        except Exception as e:
            logger.debug(f"Error reading {sys_net}: {e}")
    return interfaces


def get_ip_for_interface_cmd(iface):
    """
    Retrieve IPv4 address for a specific interface using ip command or ifconfig.
    """
    try:
        res = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3
        )
        if res.returncode == 0:
            match = re.search(r"inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", res.stdout)
            if match:
                ip = match.group(1)
                if is_valid_lan_ipv4(ip):
                    return ip
    except Exception:
        pass
    return None


def get_active_lan_ip():
    """
    Determines the current active LAN IPv4 address.
    
    Returns:
        str: Active IPv4 Address (e.g. "192.168.1.14") or None if no network detected.
    """
    # 1. Primary method: Socket routing lookup
    routed_ip = get_interface_from_route()
    if routed_ip:
        return routed_ip

    # 2. Secondary method: Enumerate physical interfaces
    physical_ifaces = get_interfaces_via_sysfs()
    for iface in physical_ifaces:
        ip = get_ip_for_interface_cmd(iface)
        if ip:
            return ip

    # 3. Tertiary fallback: Parse output of `ip -4 route show`
    try:
        res = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3
        )
        if res.returncode == 0:
            match = re.search(r"src\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", res.stdout)
            if match:
                ip = match.group(1)
                if is_valid_lan_ipv4(ip):
                    return ip
    except Exception:
        pass

    # 4. Final fallback: hostname -I
    try:
        res = subprocess.run(
            ["hostname", "-I"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3
        )
        if res.returncode == 0:
            for candidate in res.stdout.strip().split():
                if is_valid_lan_ipv4(candidate):
                    return candidate
    except Exception:
        pass

    logger.warning("No active LAN IPv4 interface found.")
    return None


def get_default_gateway():
    """
    Retrieve the current default gateway IP address.
    """
    try:
        res = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3
        )
        if res.returncode == 0:
            match = re.search(r"via\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", res.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return "N/A"


def get_active_network_details():
    """
    Retrieve active LAN IPv4, default gateway, and interface/SSID information.
    """
    ip = get_active_lan_ip()
    gateway = get_default_gateway()
    iface_name = "eth0 / wlan0"

    # Determine default interface name
    try:
        res = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3
        )
        if res.returncode == 0:
            match = re.search(r"dev\s+([a-zA-Z0-9\-\._]+)", res.stdout)
            if match:
                iface_name = match.group(1)
    except Exception:
        pass

    return {
        "ip": ip or "Disconnected",
        "gateway": gateway,
        "interface": iface_name,
        "network_name": f"{iface_name} ({ip or 'Disconnected'})"
    }

