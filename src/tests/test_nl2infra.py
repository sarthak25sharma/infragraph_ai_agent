import json

import pytest

from nl2infra.spec_models import validate_spec
from nl2infra.preview import preview_spec


def test_validate_and_preview_minimal():
    spec = {
        "infrastructure": {
            "name": "mini",
            "devices": [
                {"id": "s1", "type": "switch", "role": "spine"},
                {"id": "l1", "type": "switch", "role": "leaf"},
                {"id": "h1", "type": "server", "role": "host"},
            ],
            "links": [
                {"src": "s1", "dst": "l1"},
                {"src": "l1", "dst": "h1"},
            ],
        }
    }

    normalized = validate_spec(spec)
    text = preview_spec(normalized)
    assert "mini" in text
    assert "Devices: 3" in text
    assert "Links: 2" in text


