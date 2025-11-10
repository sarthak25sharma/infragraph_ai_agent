import json
import os
import urllib.request
import urllib.error

from .spec_models import validate_spec


def _gemini_generate(prompt: str, *, model: str = "gemini-2.5-pro", api_key: str = "") -> str:
    # Prefer explicit api_key argument; fallback to environment variable
    key = api_key or os.getenv("GOOGLE_API_KEY", "")
    if not key:
        raise RuntimeError(
            "Gemini API key not provided. Set GOOGLE_API_KEY env var or pass api_key."
        )
    url = f"https://generativelanguage.googleapis.com/v1/models/{model}:generateContent?key={key}"

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}],
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
        },
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
        raise RuntimeError(f"Gemini HTTP error: {e.code} {e.reason} | {err_body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Cannot reach Gemini API: {e.reason}")

    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception:
        raise RuntimeError("Invalid response from Gemini (not JSON)")
    candidates = parsed.get("candidates") or []
    if not candidates:
        raise RuntimeError("Gemini response missing candidates")
    content = candidates[0].get("content", {})
    parts = content.get("parts") or []
    if not parts or "text" not in parts[0]:
        raise RuntimeError("Gemini response missing content.parts[0].text")
    return parts[0]["text"]


def _build_system_prompt(schema_description: str, fewshots: str) -> str:
    return (
        "You convert a natural-language topology description into a STRICT JSON object "
        "that conforms to the InfraGraph subset schema described below.\n\n"
        "Rules:\n"
        "- Output ONLY JSON.\n"
        "- No backticks, no prose.\n"
        "- Fill required fields; omit unknowns.\n\n"
        f"Schema (subset):\n{schema_description}\n\n"
        f"Examples:\n{fewshots}\n\n"
        "Now output ONLY the JSON for the user's request."
    )


def _schema_description() -> str:
    return (
        "{\n"
        "  \"infrastructure\": {\n"
        "    \"name\": string,\n"
        "    \"devices\": [ { \"id\": string, \"type\": string, \"role\": string } ],\n"
        "    \"links\": [ { \"src\": string, \"dst\": string } ]\n"
        "  }\n"
        "}"
    )


def _fewshot_examples() -> str:
    return (
        "User: two-tier clos with 2 spines, 4 leaves, 16 hosts\n"
        "Assistant:\n"
        "{\n"
        "  \"infrastructure\": {\n"
        "    \"name\": \"two_tier_clos\",\n"
        "    \"devices\": [\n"
        "      {\"id\": \"spine1\", \"type\": \"switch\", \"role\": \"spine\"},\n"
        "      {\"id\": \"spine2\", \"type\": \"switch\", \"role\": \"spine\"},\n"
        "      {\"id\": \"leaf1\", \"type\": \"switch\", \"role\": \"leaf\"},\n"
        "      {\"id\": \"leaf2\", \"type\": \"switch\", \"role\": \"leaf\"},\n"
        "      {\"id\": \"leaf3\", \"type\": \"switch\", \"role\": \"leaf\"},\n"
        "      {\"id\": \"leaf4\", \"type\": \"switch\", \"role\": \"leaf\"}\n"
        "    ],\n"
        "    \"links\": [\n"
        "      {\"src\": \"spine1\", \"dst\": \"leaf1\"},\n"
        "      {\"src\": \"spine1\", \"dst\": \"leaf2\"},\n"
        "      {\"src\": \"spine1\", \"dst\": \"leaf3\"},\n"
        "      {\"src\": \"spine1\", \"dst\": \"leaf4\"},\n"
        "      {\"src\": \"spine2\", \"dst\": \"leaf1\"},\n"
        "      {\"src\": \"spine2\", \"dst\": \"leaf2\"},\n"
        "      {\"src\": \"spine2\", \"dst\": \"leaf3\"},\n"
        "      {\"src\": \"spine2\", \"dst\": \"leaf4\"}\n"
        "    ]\n"
        "  }\n"
        "}"
    )


def generate_spec_from_prompt(
    prompt: str,
    *,
    model: str = "gemini-2.5-pro",
    temperature: float = 0.2,
    api_key: str = "",
) -> dict:
    # We include the instruction as part of the single user turn
    system = _build_system_prompt(_schema_description(), _fewshot_examples())
    full_prompt = f"{system}\n\nUser request: {prompt}\nReturn ONLY JSON."

    # First attempt
    try:
        raw = _gemini_generate(full_prompt, model=model, api_key=api_key)
    except RuntimeError as e:
        # Retry with common aliases if 404 Model not found
        msg = str(e)
        raw = None
        if "404" in msg or "not found" in msg.lower():
            for alt in ("gemini-1.5-flash", "gemini-1.5-flash-001"):
                try:
                    raw = _gemini_generate(full_prompt, model=alt, api_key=api_key)
                    break
                except RuntimeError:
                    continue
        if raw is None:
            raise
    # Try to parse JSON directly; if that fails, try to extract JSON substring
    def _extract_json(text: str):
        try:
            return json.loads(text)
        except Exception:
            pass
        start = text.find("{")
        if start == -1:
            return None
        depth = 0
        for i in range(start, len(text)):
            ch = text[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    candidate_slice = text[start:i+1]
                    try:
                        return json.loads(candidate_slice)
                    except Exception:
                        return None
        return None

    candidate = _extract_json(raw)
    if candidate is None:
        # Attempt a single repair pass by asking for JSON only
        repair_prompt = (
            "Return ONLY valid JSON for the topology as a single JSON object with no commentary."
        )
        raw2 = _gemini_generate(repair_prompt, model=model, api_key=api_key)
        candidate = _extract_json(raw2)
        if candidate is None:
            short = (raw2 or raw or "")[:200]
            raise RuntimeError(f"Gemini did not return JSON. First 200 chars: {short}")

    # Validate and normalize
    return validate_spec(candidate)


