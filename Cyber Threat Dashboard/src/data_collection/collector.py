from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from src.utils.helpers import RAW_DATA_DIR, ensure_project_dirs


@dataclass(frozen=True)
class ThreatFeed:
    """A local threat feed definition."""

    name: str
    path: Path


class ThreatDataCollector:
    """Load threat events from local CSV feeds."""

    def __init__(self, raw_dir: Path = RAW_DATA_DIR) -> None:
        self.raw_dir = raw_dir
        ensure_project_dirs()

    def discover_feeds(self) -> list[ThreatFeed]:
        feeds = []
        for path in sorted(self.raw_dir.glob("*.csv")):
            feeds.append(ThreatFeed(name=path.stem.replace("_", " ").title(), path=path))
        return feeds

    def load_feed(self, feed: ThreatFeed) -> pd.DataFrame:
        return pd.read_csv(feed.path)

    def load_all(self) -> pd.DataFrame:
        frames = [self.load_feed(feed) for feed in self.discover_feeds()]
        if not frames:
            return pd.DataFrame()
        return pd.concat(frames, ignore_index=True)
