from typing import Optional, Dict, Any
import os
import sys

# Ensure src-based packages are importable when running directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use system env vars only

import importlib


def run_pipeline(
    prompt: str,
    *,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    location: Optional[str] = None,
    do_annotate: Optional[Dict[str, Any]] = None,
    do_query: Optional[Any] = None,
) -> Dict[str, Any]:

    # Lazy import to avoid static import resolution issues in tools
    try:
        nl2infra = importlib.import_module("nl2infra")
    except ImportError:
        nl2infra = importlib.import_module("src.nl2infra")

    # Use provided api_key or fallback to environment variable
    if api_key is None:
        api_key = os.getenv("GOOGLE_API_KEY", "")
    if not api_key:
        raise ValueError("GOOGLE_API_KEY not provided. Set it in .env file or pass api_key parameter.")
    
    # Resolve model from param or environment
    model_to_use = model or os.getenv("GEMINI_MODEL", "")

    ## ------------------the function which gets us the topospec ------------------------## 
    spec = nl2infra.generate_spec_from_prompt(prompt, model=model_to_use, api_key=api_key)
    print("Generated Spec:", spec)  # Debug print to verify spec generationj
    ## _____________________________________________________________________________________##
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
    example_prompt = str(input("Enter your infrastructure prompt: "))  
    confident = "NO"
    while confident != "YES":
        try:
            result = run_pipeline(example_prompt)
            confident = input("Are you satisfied with the result? (YES/NO): ").strip().upper()  
            
        except Exception as e:
            print(f"Error during pipeline execution: {e}")
            # Stop retrying on failure to avoid a busy/infinite loop during errors
            
        if confident != "YES":
            print("Retrying the pipeline execution...")  
            new_prompt = input("Enter revised prompt (or press Enter to keep the same): ")  
            example_prompt=new_prompt
        
    # Detailed outputs
    graph_dict = result.get("graph", {})
    nodes = graph_dict.get("nodes", [])
    edges = graph_dict.get("edges") if "edges" in graph_dict else graph_dict.get("links", [])

    print("=== Topology Summary ===")  
    print(f"Nodes: {len(nodes)} | Edges: {len(edges)}") 
    # Show sample nodes/edges
    if nodes:
        print("Sample nodes:")  
        for n in nodes[:10]:
            print(n) 
    if edges:
        print("Sample edges:")  
        for e in edges[:10]:
            print(e)  

    
    result_handle = result.get("handle")
    service = getattr(result_handle, "api", None)
    if service is not None and hasattr(service, "get_graph"):
        print("=== get_graph (YAML) ===")  
        print(service.get_graph())  
