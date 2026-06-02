from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class VMProfile:
    name: str
    vmid: str
    runtime: str = "xen"
    default_user: str = "root"


class ProfileRegistry:
    def __init__(self, profiles: list[VMProfile] | None = None) -> None:
        values = profiles or [VMProfile(name="default", vmid="100")]
        self._profiles = {p.name: p for p in values}

    def resolve(self, name: str) -> VMProfile:
        if name not in self._profiles:
            raise KeyError(f"profile not found: {name}")
        return self._profiles[name]
