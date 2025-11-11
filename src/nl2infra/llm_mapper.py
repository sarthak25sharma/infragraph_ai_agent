import json
import os
import urllib.request
import urllib.error
from typing import Optional

from .spec_models import validate_spec


def _gemini_generate(prompt: str, *, model: Optional[str] = None, api_key: str = "") -> str:
    # Resolve API key
    key = api_key or os.getenv("GOOGLE_API_KEY", "")
    if not key:
        raise RuntimeError("Gemini API key not provided. Set GOOGLE_API_KEY in your .env or pass api_key.")

    # Resolve model strictly from parameter or GEMINI_MODEL env var
    resolved_model = model or os.getenv("GEMINI_MODEL", "")
    if not resolved_model:
        raise RuntimeError("Gemini model not provided. Set GEMINI_MODEL in your .env (e.g., gemini-2.5-flash).")

    url = f"https://generativelanguage.googleapis.com/v1/models/{resolved_model}:generateContent?key={key}"

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
    return f"""
    You are a **strict schema-to-JSON translator**.

    Your task: Convert the user's natural language topology description into JSON that **exactly follows the schema** provided below. The shcema 
    follows infragraph rules any syntax. THere should be no deviation from the schema

    ### **CRITICAL GENERATION RULES**
    1. **Output ONLY JSON.**
    2. **Do NOT add comments, explanations, backticks, markdown, or extra text.**
    3. **Every key in the schema must follow the schema
    4. **If the user description does NOT specify a value, set that field to `null` or an empty list `[]` depending on its schema type or if the shcema needs it you must add some default vlue which will ensure that the schema is followed there might be some deviation in the answer but schema must be followed .**
    5. **Never add fields that are not in the schema.**
    6. **Never change key names. No synonyms. No rewording.**
    7. **Follow the examples EXACTLY in style, structure, spacing, and ordering of fields.**
    8. If the input is ambiguous, choose the **minimum assumption** (do not create extra nodes or connections).

    ### **Schema (authoritative; follow exactly)**
    {schema_description}

    ### **Few-Shot Examples (follow formatting exactly)**
    {fewshots}

    ### **Final Instruction**
    Return ONLY the JSON object. No prose, no notes, no markup.
    """


def _schema_description() -> str:
    return (
        ''' 
{
  "name": "string",
  "description": "string",
  "devices": [
    {
      "name": "string",
      "description": "string",
      "components": [
        {
          "name": "string",
          "description": "string",
          "count": 0,
          "choice": "custom",
          "custom": {
            "type": "string"
          },
          "device": {},
          "cpu": {},
          "npu": {},
          "nic": {},
          "memory": {},
          "port": {},
          "switch": {}
        }
      ],
      "links": [
        {
          "name": "string",
          "description": "string",
          "physical": {
            "bandwidth": {
              "choice": "gigabits_per_second",
              "gigabits_per_second": 0,
              "gigabytes_per_second": 0,
              "gigatransfers_per_second": 0
            },
            "latency": {
              "choice": "ms",
              "ms": 0,
              "us": 0,
              "ns": 0
            }
          }
        }
      ],
      "edges": [
        {
          "ep1": {
            "device": "string",
            "component": "string"
          },
          "ep2": {
            "device": "string",
            "component": "string"
          },
          "scheme": "one2one",
          "link": "string"
        }
      ]
    }
  ],
  "links": [
    {
      "name": "string",
      "description": "string",
      "physical": {
        "bandwidth": {
          "choice": "gigabits_per_second",
          "gigabits_per_second": 0,
          "gigabytes_per_second": 0,
          "gigatransfers_per_second": 0
        },
        "latency": {
          "choice": "ms",
          "ms": 0,
          "us": 0,
          "ns": 0
        }
      }
    }
  ],
  "instances": [
    {
      "name": "string",
      "description": "string",
      "device": "string",
      "count": 0
    }
  ],
  "edges": [
    {
      "ep1": {
        "instance": "string",
        "component": "string"
      },
      "ep2": {
        "instance": "string",
        "component": "string"
      },
      "scheme": "one2one",
      "link": "string"
    }
  ]
}'''
    )

def _fewshot_examples() -> str:
    return (
        "User: Create a ring of 4 routers.\n"
        "Assistant:\n"
        "{\n"
        '  "devices": [\n'
        '    {\n'
        '      "id": "router.0",\n'
        '      "type": "router",\n'
        '      "components": [\n'
        '        {\n'
        '          "name": "port.0",\n'
        '          "type": "interface",\n'
        '          "connections": [\n'
        '            {"target_device": "router.1", "target_component": "port.0"}\n'
        '          ]\n'
        '        },\n'
        '        {\n'
        '          "name": "port.1",\n'
        '          "type": "interface",\n'
        '          "connections": [\n'
        '            {"target_device": "router.3", "target_component": "port.1"}\n'
        '          ]\n'
        '        }\n'
        '      ]\n'
        '    },\n'
        '    {\n'
        '      "id": "router.1",\n'
        '      "type": "router",\n'
        '      "components": [\n'
        '        {\n'
        '          "name": "port.0",\n'
        '          "type": "interface",\n'
        '          "connections": [\n'
        '            {"target_device": "router.0", "target_component": "port.0"}\n'
        '          ]\n'
        '        },\n'
        '        {\n'
        '          "name": "port.1",\n'
        '          "type": "interface",\n'
        '          "connections": [\n'
        '            {"target_device": "router.2", "target_component": "port.1"}\n'
        '          ]\n'
        '        }\n'
        '      ]\n'
        '    },\n'
        '    {\n'
        '      "id": "router.2",\n'
        '      "type": "router",\n'
        '      "components": [\n'
        '        {\n'
        '          "name": "port.0",\n'
        '          "type": "interface",\n'
        '          "connections": [\n'
        '            {"target_device": "router.1", "target_component": "port.0"}\n'
        '          ]\n'
        '        },\n'
        '        {\n'
        '          "name": "port.1",\n'
        '          "type": "interface",\n'
        '          "connections": [\n'
        '            {"target_device": "router.3", "target_component": "port.1"}\n'
        '          ]\n'
        '        }\n'
        '      ]\n'
        '    },\n'
        '    {\n'
        '      "id": "router.3",\n'
        '      "type": "router",\n'
        '      "components": [\n'
        '        {\n'
        '          "name": "port.0",\n'
        '          "type": "interface",\n'
        '          "connections": [\n'
        '            {"target_device": "router.2", "target_component": "port.0"}\n'
        '          ]\n'
        '        },\n'
        '        {\n'
        '          "name": "port.1",\n'
        '          "type": "interface",\n'
        '          "connections": [\n'
        '            {"target_device": "router.0", "target_component": "port.1"}\n'
        '          ]\n'
        '        }\n'
        '      ]\n'
        '    }\n'
        '  ]\n'
        '}\n'
    )



def generate_spec_from_prompt(
    prompt: str,
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
    api_key: str = "",
) -> dict:
    # We include the instruction as part of the single user turn
    system = _build_system_prompt(_schema_description(), _fewshot_examples())
    full_prompt = f"{system}\n\nUser request: {prompt}\nReturn ONLY JSON."

    # First attempt (strictly use provided model or GEMINI_MODEL from env)
    raw = _gemini_generate(full_prompt, model=model, api_key=api_key)
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


