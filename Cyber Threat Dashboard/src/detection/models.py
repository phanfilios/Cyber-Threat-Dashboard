from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionRule:
    id: str
    name: str
    event_type: str
    base_score: int
    mitre_tactic: str
    mitre_technique: str
    recommendation: str
    description: str

    @classmethod
    def from_mapping(cls, value: dict[str, object]) -> "DetectionRule":
        return cls(
            id=str(value["id"]),
            name=str(value["name"]),
            event_type=str(value["event_type"]).lower(),
            base_score=int(value["base_score"]),
            mitre_tactic=str(value.get("mitre_tactic", "Unmapped")),
            mitre_technique=str(value.get("mitre_technique", "Unmapped")),
            recommendation=str(value.get("recommendation", "Review the event and validate surrounding activity.")),
            description=str(value.get("description", "")),
        )
