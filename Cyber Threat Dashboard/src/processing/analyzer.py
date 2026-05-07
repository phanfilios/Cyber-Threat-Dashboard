from __future__ import annotations

import pandas as pd


class ThreatAnalyzer:
    """Produce compact summaries for dashboard and reports."""

    def summarize(self, events: pd.DataFrame) -> dict[str, object]:
        if events.empty:
            return {
                "total_events": 0,
                "critical_events": 0,
                "unique_sources": 0,
                "top_asset": "N/A",
                "top_event_type": "N/A",
            }

        return {
            "total_events": int(len(events)),
            "critical_events": int((events["severity"] == "critical").sum()),
            "unique_sources": int(events["source_ip"].nunique()),
            "top_asset": str(events["asset"].mode().iat[0]),
            "top_event_type": str(events["event_type"].mode().iat[0]),
        }

    def event_type_counts(self, events: pd.DataFrame) -> pd.DataFrame:
        return (
            events.groupby("event_type", as_index=False)
            .size()
            .rename(columns={"size": "count"})
            .sort_values("count", ascending=False)
        )

    def severity_counts(self, events: pd.DataFrame) -> pd.DataFrame:
        order = ["low", "medium", "high", "critical"]
        counts = events.groupby("severity", as_index=False).size().rename(columns={"size": "count"})
        counts["severity"] = pd.Categorical(counts["severity"], categories=order, ordered=True)
        return counts.sort_values("severity")

    def timeline(self, events: pd.DataFrame) -> pd.DataFrame:
        hourly = events.set_index("timestamp").resample("h").size().reset_index(name="count")
        return hourly
