from __future__ import annotations

import pandas as pd

from src.detection.detector import ThreatDetector
from src.detection.rules import load_rules
from src.enrichment.pipeline import EnrichmentPipeline
from src.processing.parser import EventParser
from src.processing.preprocess import preprocess_events


def sample_events() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "timestamp": "2026-05-06T08:10:00Z",
                "source_ip": "185.220.101.4",
                "destination_ip": "10.0.1.12",
                "event_type": "login_failure",
                "severity": "medium",
                "asset": "vpn-gateway",
                "country": "Netherlands",
                "description": "Repeated failed VPN authentication",
            },
            {
                "timestamp": "2026-05-06T08:15:00Z",
                "source_ip": "185.220.101.4",
                "destination_ip": "10.0.1.12",
                "event_type": "login_failure",
                "severity": "high",
                "asset": "vpn-gateway",
                "country": "Netherlands",
                "description": "Credential stuffing pattern",
            },
        ]
    )


def test_parser_requires_schema() -> None:
    parser = EventParser()
    parsed = parser.parse(sample_events())

    assert parsed["timestamp"].dt.tz is not None
    assert set(parsed["severity"]) == {"medium", "high"}


def test_detector_scores_repeated_external_events_higher() -> None:
    parsed = EventParser().parse(sample_events())
    processed = preprocess_events(parsed)
    enriched = EnrichmentPipeline().enrich(processed)
    scored = ThreatDetector().score(enriched)

    assert scored["risk_score"].max() > 60
    assert scored.iloc[0]["risk_level"] in {"Medium", "High", "Critical"}
    assert scored.iloc[0]["mitre_technique"] == "T1110 Brute Force"
    assert "reputation=" in scored.iloc[0]["risk_factors"]


def test_detection_rules_load_from_yaml() -> None:
    rules = load_rules()

    assert len(rules) >= 7
    assert {rule.event_type for rule in rules} >= {"login_failure", "malware", "exfiltration"}
