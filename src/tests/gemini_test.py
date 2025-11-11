import os, json, urllib.request
import os
import sys

# Ensure src-based packages are importable when running directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

def list_models(api_key: str = "KEY_HERE") -> dict:
    key = os.getenv("GOOGLE_API_KEY")
    if not key:
        raise RuntimeError("Missing API key")

    url = f"https://generativelanguage.googleapis.com/v1/models?key={key}"
    req = urllib.request.Request(url, method="GET")

    with urllib.request.urlopen(req) as resp:
        body = resp.read().decode("utf-8")
        data = json.loads(body)
        return data

models = list_models()
for m in models["models"]:
    print(m["name"])
