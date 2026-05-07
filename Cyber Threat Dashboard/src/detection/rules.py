from __future__ import annotations

from pathlib import Path

import yaml

from src.detection.models import DetectionRule
from src.utils.helpers import CONFIG_DIR


def load_rules(path: Path | None = None) -> list[DetectionRule]:
    rules_path = path or CONFIG_DIR / "rules.yaml"
    payload = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
    rules = payload.get("rules", [])
    return [DetectionRule.from_mapping(rule) for rule in rules]


def rules_by_event_type(rules: list[DetectionRule] | None = None) -> dict[str, DetectionRule]:
    loaded_rules = rules or load_rules()
    return {rule.event_type: rule for rule in loaded_rules}
