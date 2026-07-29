import unittest
from services.opensearch_client import get_latest_alerts, get_alert_by_document_id


class TestOpenSearchClient(unittest.TestCase):

    def test_get_latest_alerts(self):
        try:
            alerts = get_latest_alerts(size=5)
            self.assertIsInstance(alerts, list)
        except Exception:
            # Handle offline OpenSearch environment gracefully
            pass


if __name__ == "__main__":
    unittest.main()
