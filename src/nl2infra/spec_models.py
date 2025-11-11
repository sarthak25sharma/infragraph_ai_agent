from typing import List
from pydantic import BaseModel, Field, ValidationError

class Device(BaseModel):
    id: str = Field(..., description="Unique device identifier")
    type: str = Field(..., description="Device type, e.g., switch, server")
    role: str = Field(..., description="Role in topology, e.g., spine, leaf, host")

class Link(BaseModel):
    src: str = Field(..., description="Source device id")
    dst: str = Field(..., description="Destination device id")

class Infrastructure(BaseModel):
    name: str = Field(...)
    devices: List[Device] = Field(default_factory=list)
    links: List[Link] = Field(default_factory=list)

class InfraGraphSpec(BaseModel):
    infrastructure: Infrastructure

def _looks_infragraph_like(obj: dict) -> bool:
    # Heuristic: full InfraGraph uses device 'name'/components/links/edges keys
    devs = obj.get("devices") if isinstance(obj, dict) else None
    if isinstance(devs, list) and devs and isinstance(devs[0], dict):
        d0 = devs[0]
        return ("name" in d0) or ("components" in d0) or ("edges" in d0)
    return False

def validate_spec(spec: dict) -> dict:
    # Accept both {"infrastructure": {...}} and plain {...}
    root = spec.get("infrastructure", spec)

    # If it looks like a full InfraGraph spec, accept as-is
    if _looks_infragraph_like(root):
        return {"infrastructure": root}

    # Otherwise validate the simplified schema
    try:
        normalized = InfraGraphSpec.model_validate({"infrastructure": root})
    except ValidationError as e:
        raise e
    return normalized.model_dump(exclude_none=True)