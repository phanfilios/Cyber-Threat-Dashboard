from __future__ import annotations

import pandas as pd


REQUIRED_COLUMNS = {
    "timestamp",
    "source_ip",
    "destination_ip",
    "event_type",
    "severity",
    "asset",
    "country",
    "description",
}


class EventParser:
    """Validate and normalize raw event records."""

    def parse(self, events: pd.DataFrame) -> pd.DataFrame:
        missing = REQUIRED_COLUMNS.difference(events.columns)
        if missing:
            missing_list = ", ".join(sorted(missing))
            raise ValueError(f"Missing required event columns: {missing_list}")

        parsed = events.copy()
        parsed["timestamp"] = pd.to_datetime(parsed["timestamp"], utc=True, errors="coerce")
        parsed["event_type"] = parsed["event_type"].astype(str).str.strip().str.lower()
        parsed["severity"] = parsed["severity"].astype(str).str.strip().str.lower()
        parsed["asset"] = parsed["asset"].astype(str).str.strip()
        parsed["country"] = parsed["country"].astype(str).str.strip().replace("", "Unknown")
        parsed["description"] = parsed["description"].astype(str).str.strip()
        parsed = parsed.dropna(subset=["timestamp", "source_ip", "destination_ip"])
        return parsed
