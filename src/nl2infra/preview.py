def preview_spec(spec: dict) -> str:
    infra = spec.get("infrastructure", {})
    name = infra.get("name", "<unnamed>")
    devices = infra.get("devices", [])
    links = infra.get("links", [])

    # Count by role/type
    by_role = {}
    by_type = {}
    for d in devices:
        by_role[d.get("role", "")] = by_role.get(d.get("role", ""), 0) + 1
        by_type[d.get("type", "")] = by_type.get(d.get("type", ""), 0) + 1

    lines = []
    lines.append(f"Topology: {name}")
    lines.append(f"Devices: {len(devices)} | Links: {len(links)}")
    if by_role:
        lines.append("By role:")
        for r, c in sorted(by_role.items()):
            lines.append(f"  - {r}: {c}")
    if by_type:
        lines.append("By type:")
        for t, c in sorted(by_type.items()):
            lines.append(f"  - {t}: {c}")

    # Tiny sample of first few links
    preview_links = links[:8]
    if preview_links:
        lines.append("Sample links:")
        for ln in preview_links:
            lines.append(f"  - {ln.get('src')} -> {ln.get('dst')}")

    return "\n".join(lines)


