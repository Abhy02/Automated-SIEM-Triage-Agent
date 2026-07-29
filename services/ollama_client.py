import requests


class OllamaClient:

    URL = "http://localhost:11434/api/generate"

    MODEL = "llama3.2:3b"

    @classmethod
    def generate(cls, prompt: str) -> str:

        payload = {
            "model": cls.MODEL,
            "prompt": prompt,
            "stream": False
        }

        response = requests.post(
            cls.URL,
            json=payload,
            timeout=120
        )

        response.raise_for_status()

        return response.json()["response"]
