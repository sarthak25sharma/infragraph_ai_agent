from typing import Optional, Dict, Any
import os
import sys

# Ensure src-based packages are importable when running directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import importlib


def run_pipeline(
    prompt: str,
    *,
    model: str = "gemini-2.5-pro",
    api_key: str = "KEY_HERE",
    location: Optional[str] = None,
    do_annotate: Optional[Dict[str, Any]] = None,
    do_query: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Run the end-to-end InfraGraph pipeline from a natural-language prompt.

    - Generates an InfraGraph JSON spec using a local Gemini call (HTTP API)
    - Validates and previews the spec
    - Builds the graph via existing InfraGraph client (gRPC)
    - Optionally annotates and queries
    - Exports the resulting graph

    Returns a dict with: spec, preview, handle, graph, query_result
    """
    # Lazy import to avoid static import resolution issues in tools
    try:
        nl2infra = importlib.import_module("nl2infra")
    except ImportError:
        nl2infra = importlib.import_module("src.nl2infra")

    spec = nl2infra.generate_spec_from_prompt(prompt, model=model, api_key=api_key)
    spec = nl2infra.validate_spec(spec)
    preview = nl2infra.preview_spec(spec)
    handle = nl2infra.build_graph(spec, location=location)

    if do_annotate:
        nl2infra.annotate_graph(handle, do_annotate)

    query_result = None
    if do_query is not None:
        query_result = nl2infra.query_graph(handle, do_query)

    graph = nl2infra.export_graph(handle)
    return {
        "spec": spec,
        "preview": preview,
        "handle": handle,
        "graph": graph,
        "query_result": query_result,
    }


if __name__ == "__main__":
    # Minimal demonstration (not a full CLI)
    example_prompt='''

2 Spine switches: spine.0, spine.1

4 Leaf switches: leaf.0 – leaf.3

16 Hosts total, 4 per leaf:

leaf.0 → hosts host.0–host.3

leaf.1 → hosts host.4–host.7

leaf.2 → hosts host.8–host.11

leaf.3 → hosts host.12–host.15

Each leaf uplinks to both spines (full mesh leaf→spine)

Each host has 1 NIC (for clarity & correctness)
'''
    #example_prompt = "two-tier CLOS with 2 spines, 4 leaves, 16 hosts, if any details are missing assume reasonable defaults"
    result = run_pipeline(example_prompt, api_key="KEY_HERE")

    # Detailed outputs
    graph_dict = result.get("graph", {})
    nodes = graph_dict.get("nodes", [])
    edges = graph_dict.get("edges") if "edges" in graph_dict else graph_dict.get("links", [])

    print("=== Topology Summary ===")  # noqa: T201
    print(f"Nodes: {len(nodes)} | Edges: {len(edges)}")  # noqa: T201
    # Show sample nodes/edges
    if nodes:
        print("Sample nodes:")  # noqa: T201
        for n in nodes:
            print(n)  # noqa: T201
    if edges:
        print("Sample edges:")  # noqa: T201
        for e in edges:
            print(e)  # noqa: T201

    # Print full graph via service get_graph()
    handle = result.get("handle")
    service = getattr(handle, "api", None)
    if service is not None and hasattr(service, "get_graph"):
        print("=== get_graph (YAML) ===")  # noqa: T201
        print(service.get_graph())  # noqa: T201
