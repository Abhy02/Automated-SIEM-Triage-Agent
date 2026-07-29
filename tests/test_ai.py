import unittest
from services.ai_copilot import AICopilot


class TestAICopilot(unittest.TestCase):

    def test_copilot_class_structure(self):
        self.assertTrue(hasattr(AICopilot, "ask"))

    def test_copilot_ask_fallback(self):
        res = AICopilot.ask("Generate Linux commands for triage")
        self.assertIsNotNone(res)
        self.assertTrue(len(res) > 0)


if __name__ == "__main__":
    unittest.main()
