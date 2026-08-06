import os
import requests
import urllib3
from dotenv import load_dotenv
from config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()


def get_wazuh_host():
    raw_host = os.getenv("WAZUH_HOST", Config.WAZUH_HOST or "https://127.0.0.1:55000")
    if not raw_host.startswith("http"):
        raw_host = f"https://{raw_host}"
    return raw_host.rstrip("/")


def get_token():
    host = get_wazuh_host()
    username = os.getenv("WAZUH_USERNAME", Config.WAZUH_USER or "admin")
    password = os.getenv("WAZUH_PASSWORD", Config.WAZUH_PASS or "SecretPassword")

    url = host if ":55000" in host else f"{host}:55000"
    url = f"{url}/security/user/authenticate"

    response = requests.get(
        url,
        auth=(username, password),
        verify=False,
        timeout=5
    )

    response.raise_for_status()
    return response.json()["data"]["token"]


def get_latest_alerts(limit=5):
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}

    host = get_wazuh_host()
    base_url = host if ":55000" in host else f"{host}:55000"
    url = f"{base_url}/alerts?limit={limit}&sort=-timestamp"

    response = requests.get(
        url,
        headers=headers,
        verify=False,
        timeout=5
    )

    response.raise_for_status()
    return response.json()
