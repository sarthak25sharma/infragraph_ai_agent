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


def validate_spec(spec: dict) -> dict:
    try:
        normalized = InfraGraphSpec.model_validate(spec)
    except ValidationError as e:
        raise e
    return normalized.model_dump(exclude_none=True)


