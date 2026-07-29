"""
AISOC Enterprise - Demo Mode Telemetry Provider
Provides a clean, static set of sample Wazuh SIEM alerts when OpenSearch is offline or in Demo Mode.
No random fake alerts are generated.
"""

DEMO_ALERTS = [
    {
        "_id": "DEMO-ALERT-5710",
        "_source": {
            "@timestamp": "2026-07-29T18:08:08Z",
            "rule": {
                "id": "5710",
                "level": 10,
                "description": "sshd: Attempt to login using non-existent user",
                "groups": ["sshd", "authentication_failed"]
            },
            "agent": {
                "id": "001",
                "name": "kali-soc-node",
                "ip": "192.168.1.61",
                "os": {"name": "Linux"}
            },
            "predecoder": {
                "hostname": "kali-soc-node"
            },
            "full_log": "Jul 29 18:08:08 kali-soc-node sshd[14201]: Invalid user admin from 198.51.100.42 port 44321",
            "location": "/var/log/auth.log"
        }
    },
    {
        "_id": "DEMO-ALERT-533",
        "_source": {
            "@timestamp": "2026-07-29T18:02:14Z",
            "rule": {
                "id": "533",
                "level": 7,
                "description": "Listened ports status (netstat) changed",
                "groups": ["ossec", "netstat"]
            },
            "agent": {
                "id": "001",
                "name": "kali-soc-node",
                "ip": "192.168.1.61",
                "os": {"name": "Linux"}
            },
            "predecoder": {
                "hostname": "kali-soc-node"
            },
            "full_log": "ossec: output: 'netstat listening ports': tcp 0.0.0.0:9200 0.0.0.0:* 2308/docker-proxy",
            "location": "netstat listening ports"
        }
    },
    {
        "_id": "DEMO-ALERT-81101",
        "_source": {
            "@timestamp": "2026-07-29T18:04:00Z",
            "rule": {
                "id": "81101",
                "level": 6,
                "description": "USB storage device attached",
                "groups": ["syslog", "usb"]
            },
            "agent": {
                "id": "002",
                "name": "finance-workstation-01",
                "ip": "192.168.1.105",
                "os": {"name": "Windows"}
            },
            "predecoder": {
                "hostname": "finance-workstation-01"
            },
            "full_log": "kernel: [1204.12] usb 1-1: New USB device found, idVendor=0781, idProduct=5581 (SanDisk)",
            "location": "/var/log/syslog"
        }
    }
]


def get_demo_alerts() -> list:
    """
    Returns the clean, static sample Wazuh SIEM alert dataset.
    No random alerts are generated.
    """
    return DEMO_ALERTS
