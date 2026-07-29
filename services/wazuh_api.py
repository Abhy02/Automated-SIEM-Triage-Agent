import os
import requests
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("WAZUH_HOST")
USERNAME = os.getenv("WAZUH_USERNAME")
PASSWORD = os.getenv("WAZUH_PASSWORD")


def get_token():
    url = f"{HOST}:55000/security/user/authenticate"

    response = requests.get(
        url,
        auth=(USERNAME, PASSWORD),
        verify=False
    )

    response.raise_for_status()

    return response.json()["data"]["token"]


def get_latest_alerts(limit=5):
    token = get_token()

    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = (
        f"{HOST}:55000/alerts"
        f"?limit={limit}"
        "&sort=-timestamp"
    )

    response = requests.get(
        url,
        headers=headers,
        verify=False
    )

    response.raise_for_status()

    return response.json()
