import unittest
from threat_intel.intel_engine import enrich_iocs


class TestThreatIntel(unittest.TestCase):

    def test_enrich_iocs_structure(self):
        sample_iocs = {
            "ips": [{"ip": "8.8.8.8", "type": "Public"}, {"ip": "192.168.1.1", "type": "Private"}],
            "hashes": [],
            "domains": [],
            "urls": []
        }
        results = enrich_iocs(sample_iocs)
        self.assertIsInstance(results, list)


if __name__ == "__main__":
    unittest.main()
