import json
import logging
import re

logger = logging.getLogger(__name__)


class ResponseParser:

    @staticmethod
    def parse(raw_text: str) -> dict:
        """
        Parse raw LLM string into a structured JSON report dictionary.
        Extracts JSON block if surrounded by markdown code fences.
        """
        if not raw_text:
            return {}

        clean_text = raw_text.strip()
        if "```" in clean_text:
            match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", clean_text, re.DOTALL)
            if match:
                clean_text = match.group(1)

        try:
            return json.loads(clean_text)
        except Exception as e:
            logger.warning("Failed to parse LLM response as JSON: %s. Attempting regex extract.", str(e))
            match = re.search(r"(\{.*\})", clean_text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except Exception:
                    pass

        return {
            "summary": clean_text[:300],
            "root_cause": "Parsing unformatted LLM response.",
            "classification": "Unknown",
            "confidence": "Medium (75%)"
        }
