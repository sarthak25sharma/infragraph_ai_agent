import os, json, urllib.request

def list_models(api_key: str = "KEY_HERE") -> dict:
    key = api_key or os.getenv("GOOGLE_git")
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
