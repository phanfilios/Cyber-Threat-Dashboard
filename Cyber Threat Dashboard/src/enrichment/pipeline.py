from __future__ import annotations

import pandas as pd

from src.enrichment.assets import AssetInventory
from src.enrichment.reputation import ReputationEnricher


class EnrichmentPipeline:
    def __init__(self) -> None:
        self.asset_inventory = AssetInventory()
        self.reputation = ReputationEnricher()

    def enrich(self, events: pd.DataFrame) -> pd.DataFrame:
        enriched = self.asset_inventory.enrich(events)
        enriched = self.reputation.enrich(enriched)
        return enriched
