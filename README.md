[![PyPI](https://img.shields.io/pypi/v/infragraph)](https://pypi.org/project/infragraph/)
# InfraGraph (INFRAstructure GRAPH)

InfraGraph defines a [model-driven, vendor-neutral API](https://infragraph.dev/openapi.html) for capturing a system of systems suitable for use in co-designing AI/HPC solutions.

The model and API allows for defining physical infrastructure using a standardized graph like terminology.

In addition to the base graph definition, user provided `annotations` can `extend the graph` allowing for an unlimited number of different physical and/or logical characteristics/view.

Additional information such as background, schema and examples can be found in the [online documentation](https://infragraph.dev).

## NL → InfraGraph (Python API)

The `nl2infra` module provides a minimal pipeline to convert a natural-language prompt into an InfraGraph spec, validate/preview it, and build the topology using the existing InfraGraph client.

Example (Gemini):

```python
from nl2infra import generate_spec_from_prompt, validate_spec, preview_spec, build_graph, export_graph
import os

# 1) Generate spec from NL
os.environ["GOOGLE_API_KEY"] = ""  # insert your key
spec = generate_spec_from_prompt("two-tier CLOS with 2 spines, 4 leaves, 16 hosts")

# 2) Validate (no-op if already valid)
spec = validate_spec(spec)

# 3) Preview
print(preview_spec(spec))

# 4) Build graph (requires InfraGraph backend available; defaults to localhost:50051)
handle = build_graph(spec)

# 5) Export current graph
graph = export_graph(handle)
```

See InfraGraph docs for schema details: https://infragraph.dev/

Contributions can be made in the following ways:
- [open an issue](https://github.com/keysight/infragraph/issues) in the repository
- [fork the models repository](https://github.com/keysight/infragraph) and submit a PR