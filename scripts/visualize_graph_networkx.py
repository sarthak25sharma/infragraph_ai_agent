
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Iterable, List, Tuple

import matplotlib.pyplot as plt
import networkx as nx


def load_graph(path: str) -> Dict[str, Any]:
    if not path or path == "-":
        data = json.load(sys.stdin)
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    return data


def normalize_nodes(nodes: Iterable[Any]) -> List[Tuple[str, Dict[str, Any]]]:
    out = []
    for n in nodes:
        if isinstance(n, dict):
            nid = str(n.get("id") or n.get("name") or n.get("uid") or n.get("label"))
            attrs = dict(n)
            attrs.setdefault("label", attrs.get("label") or attrs.get("name") or nid)
        else:
            nid = str(n)
            attrs = {"label": nid}
        out.append((nid, attrs))
    return out


def normalize_edges(edges: Iterable[Any]) -> List[Tuple[str, str, Dict[str, Any]]]:
    out = []
    for e in edges:
        if isinstance(e, dict):
            src = str(e.get("source") or e.get("from") or e.get("src") or e.get("u") or e.get("a"))
            dst = str(e.get("target") or e.get("to") or e.get("dst") or e.get("v") or e.get("b"))
            attrs = dict(e)
        elif isinstance(e, (list, tuple)):
            if len(e) >= 2:
                src = str(e[0])
                dst = str(e[1])
                attrs = {"label": e[2]} if len(e) > 2 else {}
            else:
                continue
        else:
            # unknown edge format, skip
            continue
        out.append((src, dst, attrs))
    return out


def build_nx_graph(graph: Dict[str, Any]) -> nx.DiGraph:
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", graph.get("links", []))

    G = nx.DiGraph()

    for nid, attrs in normalize_nodes(nodes):
        G.add_node(nid, **attrs)

    for src, dst, attrs in normalize_edges(edges):
        if not G.has_node(src):
            G.add_node(src, label=str(src))
        if not G.has_node(dst):
            G.add_node(dst, label=str(dst))
        G.add_edge(src, dst, **attrs)

    return G


def draw_graph(
    G: nx.Graph,
    out_path: str,
    layout: str = "spring",
    figsize: Tuple[int, int] = (12, 8),
    show_edge_labels: bool = False,
):
    plt.figure(figsize=figsize)

    if layout == "spring":
        pos = nx.spring_layout(G, seed=42)
    elif layout == "kamada":
        pos = nx.kamada_kawai_layout(G)
    elif layout == "circular":
        pos = nx.circular_layout(G)
    elif layout == "shell":
        pos = nx.shell_layout(G)
    else:
        pos = nx.spring_layout(G, seed=42)

    # node labels
    labels = {n: data.get("label", str(n)) for n, data in G.nodes(data=True)}

    # node sizes by degree (clamped)
    deg = dict(G.degree())
    sizes = [300 + 100 * min(10, deg.get(n, 0)) for n in G.nodes()]

    # color nodes by optional 'type' or 'kind'
    types = [G.nodes[n].get("type") or G.nodes[n].get("kind") or "_" for n in G.nodes()]
    unique_types = {t: i for i, t in enumerate(sorted(set(types)))}
    colors = [unique_types[t] for t in types]

    nx.draw_networkx_nodes(G, pos, node_size=sizes, cmap=plt.cm.tab20, node_color=colors)
    nx.draw_networkx_edges(G, pos, arrows=True, arrowstyle="-|>", arrowsize=12)
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=8)

    if show_edge_labels:
        edge_labels = { (u, v): d.get("label") or d.get("name") or "" for u, v, d in G.edges(data=True) }
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7)

    plt.axis("off")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()


def parse_args():
    p = argparse.ArgumentParser(description="Visualize graph JSON using NetworkX")
    p.add_argument("input", nargs="?", help="Path to graph JSON file (or '-' for stdin)")
    p.add_argument("-o", "--output", default="graph.png", help="Output image path (PNG)")
    p.add_argument("--layout", choices=["spring", "kamada", "circular", "shell"], default="spring")
    p.add_argument("--width", type=int, default=12, help="Figure width in inches")
    p.add_argument("--height", type=int, default=8, help="Figure height in inches")
    p.add_argument("--edge-labels", action="store_true", help="Render edge labels")
    return p.parse_args()


def main():
    args = parse_args()
    data = load_graph(args.input) if args.input else load_graph("-")
    G = build_nx_graph(data)
    draw_graph(G, args.output, layout=args.layout, figsize=(args.width, args.height), show_edge_labels=args.edge_labels)
    print("Saved:", args.output)


if __name__ == "__main__":
    main()
