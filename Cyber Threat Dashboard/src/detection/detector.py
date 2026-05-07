from __future__ import annotations

import numpy as np
import pandas as pd

from src.detection.models import DetectionRule
from src.detection.rules import rules_by_event_type


DEFAULT_RULE = DetectionRule(
    id="unclassified_signal",
    name="Unclassified Signal",
    event_type="unclassified",
    base_score=15,
    mitre_tactic="Unmapped",
    mitre_technique="Unmapped",
    recommendation="Review the event and validate surrounding activity.",
    description="No specific rule matched this event.",
)


class ThreatDetector:
    """Score events using transparent, explainable detection logic."""

    def __init__(self, rules: dict[str, DetectionRule] | None = None) -> None:
        self.rules = rules or rules_by_event_type()

    def score(self, events: pd.DataFrame) -> pd.DataFrame:
        scored = events.copy()
        matched_rules = scored["event_type"].map(lambda value: self.rules.get(value, DEFAULT_RULE))
        scored["rule_id"] = matched_rules.map(lambda rule: rule.id)
        scored["rule_name"] = matched_rules.map(lambda rule: rule.name)
        scored["rule_description"] = matched_rules.map(lambda rule: rule.description)
        scored["mitre_tactic"] = matched_rules.map(lambda rule: rule.mitre_tactic)
        scored["mitre_technique"] = matched_rules.map(lambda rule: rule.mitre_technique)
        scored["recommendation"] = matched_rules.map(lambda rule: rule.recommendation)
        scored["base_score"] = matched_rules.map(lambda rule: rule.base_score)

        recurrence = scored.groupby("event_fingerprint")["event_fingerprint"].transform("size")
        external_bonus = np.where(scored["is_external"], 10, 0)
        recurrence_bonus = np.clip((recurrence - 1) * 8, 0, 24)
        severity_bonus = scored["severity_score"] * 8
        asset_bonus = np.clip((scored.get("asset_criticality", 2) - 1) * 5, 0, 20)
        reputation_bonus = scored.get("reputation_score", 0)

        scored["risk_score"] = np.clip(
            scored["base_score"] + severity_bonus + external_bonus + recurrence_bonus + asset_bonus + reputation_bonus,
            0,
            100,
        ).astype(int)
        scored["risk_level"] = pd.cut(
            scored["risk_score"],
            bins=[-1, 39, 69, 84, 100],
            labels=["Low", "Medium", "High", "Critical"],
        ).astype(str)
        scored["risk_factors"] = [
            self._risk_factors(row, int(recurrence.iloc[index]), int(recurrence_bonus[index]), int(asset_bonus.iloc[index] if hasattr(asset_bonus, "iloc") else asset_bonus))
            for index, row in scored.iterrows()
        ]
        return scored.sort_values(["risk_score", "timestamp"], ascending=[False, False]).reset_index(drop=True)

    def top_incidents(self, events: pd.DataFrame, limit: int = 10) -> pd.DataFrame:
        return self.score(events).head(limit)

    def _risk_factors(self, row: pd.Series, recurrence: int, recurrence_bonus: int, asset_bonus: int) -> str:
        factors = [
            f"rule={row['rule_name']} +{row['base_score']}",
            f"severity={row['severity']} +{row['severity_score'] * 8}",
        ]
        if row["is_external"]:
            factors.append("external_source +10")
        if recurrence > 1:
            factors.append(f"recurrence={recurrence} +{recurrence_bonus}")
        if asset_bonus:
            factors.append(f"asset_criticality={row.get('asset_criticality', 2)} +{asset_bonus}")
        if row.get("reputation_score", 0):
            factors.append(f"reputation={row.get('reputation_label', 'Watched')} +{row['reputation_score']}")
        return "; ".join(factors)
