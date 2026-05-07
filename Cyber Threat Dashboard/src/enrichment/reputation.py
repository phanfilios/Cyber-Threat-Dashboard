from __future__ import annotations

import ipaddress

import pandas as pd


HIGH_RISK_COUNTRIES = {"Unknown", "Russia", "Netherlands"}
SUSPICIOUS_EVENT_TYPES = {"malware", "exfiltration", "phishing", "login_failure"}


def classify_ip_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return "invalid"

    if address.is_private:
        return "private"
    if address.is_loopback:
        return "loopback"
    if address.is_reserved:
        return "reserved"
    return "public"


class ReputationEnricher:
    """Offline reputation heuristics for demo and local analysis."""

    def enrich(self, events: pd.DataFrame) -> pd.DataFrame:
        enriched = events.copy()
        enriched["source_ip_class"] = enriched["source_ip"].map(classify_ip_address)
        enriched["destination_ip_class"] = enriched["destination_ip"].map(classify_ip_address)
        enriched["geo_risk"] = enriched["country"].map(lambda country: 12 if country in HIGH_RISK_COUNTRIES else 0)
        enriched["reputation_score"] = enriched.apply(self._score_reputation, axis=1).astype(int)
        enriched["reputation_label"] = enriched["reputation_score"].map(self._label_reputation)
        return enriched

    def _score_reputation(self, row: pd.Series) -> int:
        score = 0
        if row["source_ip_class"] == "public":
            score += 8
        if row["country"] in HIGH_RISK_COUNTRIES:
            score += 12
        if row["event_type"] in SUSPICIOUS_EVENT_TYPES:
            score += 10
        return min(score, 30)

    def _label_reputation(self, score: int) -> str:
        if score >= 24:
            return "Hostile"
        if score >= 14:
            return "Suspicious"
        if score > 0:
            return "Watched"
        return "Neutral"
