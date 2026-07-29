import logging
import os
import urllib3
from opensearchpy import OpenSearch
from config import Config
from services.demo_data_service import get_demo_alerts

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", os.getenv("INDEXER_HOST", "https://192.168.1.61:9200"))
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", os.getenv("INDEXER_USERNAME", "admin"))
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS", os.getenv("INDEXER_PASSWORD", "admin"))

try:
    client = OpenSearch(
        hosts=[OPENSEARCH_HOST],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        verify_certs=False,
        ssl_show_warn=False,
        timeout=5,
    )
except Exception as e:
    logger.warning("OpenSearch client initialization failed: %s.", str(e))
    client = None


def get_latest_alerts(size: int = 100) -> list:
    """
    Fetch latest Wazuh SIEM alerts directly from OpenSearch sorted by @timestamp DESC.
    Strictly read-only: never modifies, generates, or seeds data.
    Only uses static demo alerts if DEMO_MODE is explicitly enabled.
    """
    if client is None:
        if Config.DEMO_MODE:
            logger.info("OpenSearch client offline. Demo Mode active: Returning static demo alerts.")
            return get_demo_alerts()[:size]
        logger.warning("OpenSearch client offline in Production Mode. Returning empty alert list.")
        return []

    query = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
    }

    try:
        response = client.search(index="wazuh-alerts-*", body=query)
        hits = response.get("hits", {}).get("hits", [])
        total_hits = response.get("hits", {}).get("total", {}).get("value", len(hits))

        logger.info("OpenSearch Total: %d | Returned: %d | Index: wazuh-alerts-*", total_hits, len(hits))

        if not hits:
            if Config.DEMO_MODE:
                return get_demo_alerts()[:size]
            return []
        return hits
    except Exception as e:
        logger.warning("OpenSearch query failed (%s).", str(e))
        if Config.DEMO_MODE:
            return get_demo_alerts()[:size]
        return []


def get_alert_by_document_id(doc_id: str) -> dict:
    """
    Fetch raw alert document by document ID. Strictly read-only query.
    """
    if client:
        try:
            response = client.search(
                index="wazuh-alerts-*",
                body={"query": {"ids": {"values": [doc_id]}}},
            )
            hits = response.get("hits", {}).get("hits", [])
            if hits:
                return hits[0]["_source"]
        except Exception as e:
            logger.warning("OpenSearch document query failed for %s: %s", doc_id, str(e))

    if Config.DEMO_MODE:
        for item in get_demo_alerts():
            if item["_id"] == doc_id:
                return item["_source"]

    return None

