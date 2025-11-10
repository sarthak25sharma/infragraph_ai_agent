from dataclasses import dataclass
from typing import Any, Optional, Dict, List
import json
import yaml

from infragraph.infragraph import Infrastructure
from infragraph.infragraph_service import InfraGraphService


@dataclass
class InfragraphHandle:
    api: Any
    is_local: bool = False


def build_graph(spec: dict, *, location: Optional[str] = None) -> InfragraphHandle:
    # Always use the in-process service for MVP simplicity
    raw = spec.get("infrastructure", spec)
    payload = _coerce_to_infragraph(raw)
    service = InfraGraphService()
    infra_obj = Infrastructure().deserialize(json.dumps(payload))
    service.set_graph(infra_obj)
    return InfragraphHandle(api=service, is_local=True)


def annotate_graph(handle: InfragraphHandle, annotations: dict) -> None:
    if handle.is_local:
        # Local annotate requires an AnnotateRequest; not implemented in MVP
        raise NotImplementedError("annotate_graph not implemented for local service fallback")
    handle.api.annotate_graph(annotations)


def query_graph(handle: InfragraphHandle, query: Any) -> Any:
    if handle.is_local:
        # Local query requires a QueryRequest; not implemented in MVP
        raise NotImplementedError("query_graph not implemented for local service fallback")
    return handle.api.query_graph(query)


def export_graph(handle: InfragraphHandle) -> dict:
    if handle.is_local:
        # Local service returns YAML string from get_graph()
        data = handle.api.get_graph()
        return yaml.safe_load(data)
    res = handle.api.get_graph({})
    return res.serialize() if hasattr(res, "serialize") else res


def _coerce_to_infragraph(raw: dict) -> dict:
    """
    Convert a simplified spec (with devices: id/type/role and links: src/dst) into
    a compliant InfraGraph Infrastructure dict.

    If the input already looks compliant (has 'instances' or device components), return as-is.
    """
    if _looks_compliant(raw):
        return raw

    infra = raw
    devices: List[Dict[str, Any]] = infra.get("devices", [])
    links: List[Dict[str, Any]] = infra.get("links", [])

    role_counts: Dict[str, int] = {"spine": 0, "leaf": 0, "host": 0}
    name_to_role: Dict[str, str] = {}
    for d in devices:
        role = d.get("role") or d.get("type")
        did = d.get("id") or d.get("name")
        if role and did:
            name_to_role[did] = role
            if role in role_counts:
                role_counts[role] += 1

    # Compute per-leaf host count if possible
    leaf_to_hosts = {}
    for ln in links:
        s = ln.get("src")
        t = ln.get("dst")
        if not s or not t:
            continue
        # Normalize undirected for simple input
        pairs = [(s, t), (t, s)]
        for a, b in pairs:
            if name_to_role.get(a) == "leaf" and name_to_role.get(b) == "host":
                leaf_to_hosts[a] = leaf_to_hosts.get(a, 0) + 1

    num_spines = role_counts["spine"]
    num_leaves = role_counts["leaf"]
    num_hosts = role_counts["host"]
    hosts_per_leaf = max(leaf_to_hosts.values()) if leaf_to_hosts else (num_hosts // num_leaves if num_leaves else 0)

    # Define generic devices with required components/links/edges
    ig_devices: List[Dict[str, Any]] = []
    if num_spines:
        ig_devices.append({
            "name": "spine",
            "components": [
                {"name": "port", "count": max(1, num_leaves), "choice": "port"}
            ],
            "links": [],
            "edges": [],
        })
    if num_leaves:
        ig_devices.append({
            "name": "leaf",
            "components": [
                {"name": "port", "count": max(1, max(num_spines, hosts_per_leaf)), "choice": "port"}
            ],
            "links": [],
            "edges": [],
        })
    if num_hosts:
        ig_devices.append({
            "name": "host",
            "components": [
                {"name": "nic", "count": max(1, hosts_per_leaf), "choice": "nic"}
            ],
            "links": [],
            "edges": [],
        })

    ig_links: List[Dict[str, Any]] = []
    if num_spines and num_leaves:
        ig_links.append({"name": "fabric"})
    if num_leaves and num_hosts:
        ig_links.append({"name": "access"})

    ig_instances: List[Dict[str, Any]] = []
    if num_spines:
        ig_instances.append({"name": "spine", "device": "spine", "count": num_spines})
    if num_leaves:
        ig_instances.append({"name": "leaf", "device": "leaf", "count": num_leaves})
    if num_hosts:
        # Represent total hosts as (num_leaves instances) x (hosts_per_leaf nics per instance)
        ig_instances.append({"name": "host", "device": "host", "count": max(1, num_leaves)})

    ig_edges: List[Dict[str, Any]] = []
    if num_spines and num_leaves:
        ig_edges.append({
            "ep1": {"instance": "spine[0:%d]" % num_spines, "component": "port[0:%d]" % max(1, num_leaves)},
            "ep2": {"instance": "leaf[0:%d]" % num_leaves, "component": "port[0:%d]" % max(1, num_spines)},
            "scheme": "many2many",
            "link": "fabric",
        })
    if num_leaves and num_hosts:
        ig_edges.append({
            "ep1": {"instance": "leaf[0:%d]" % num_leaves, "component": "port[0:%d]" % max(1, hosts_per_leaf)},
            "ep2": {"instance": "host[0:%d]" % max(1, num_leaves), "component": "nic[0:%d]" % max(1, hosts_per_leaf)},
            "scheme": "many2many",
            "link": "access",
        })

    return {
        "name": infra.get("name", "generated_topology"),
        "devices": ig_devices,
        "links": ig_links,
        "instances": ig_instances,
        "edges": ig_edges,
    }


def _looks_compliant(raw: dict) -> bool:
    # heuristic: if there are 'instances' or device components present
    if "instances" in raw:
        return True
    devs = raw.get("devices")
    if isinstance(devs, list) and devs and isinstance(devs[0], dict) and "components" in devs[0]:
        return True
    return False


