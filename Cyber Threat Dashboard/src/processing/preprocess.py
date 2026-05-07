from __future__ import annotations

import pandas as pd


SEVERITY_SCORE = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def preprocess_events(events: pd.DataFrame) -> pd.DataFrame:
    cleaned = events.copy()
    cleaned["severity_score"] = cleaned["severity"].map(SEVERITY_SCORE).fillna(1).astype(int)
    cleaned["hour"] = cleaned["timestamp"].dt.hour
    cleaned["date"] = cleaned["timestamp"].dt.date.astype(str)
    cleaned["is_external"] = ~cleaned["source_ip"].astype(str).str.startswith(("10.", "172.16.", "192.168."))
    cleaned["event_fingerprint"] = (
        cleaned["source_ip"].astype(str)
        + "|"
        + cleaned["destination_ip"].astype(str)
        + "|"
        + cleaned["event_type"].astype(str)
    )
    return cleaned.sort_values("timestamp").reset_index(drop=True)
