from __future__ import annotations

from pathlib import Path

import pandas as pd
import yaml

from src.utils.helpers import CONFIG_DIR


DEFAULT_ASSET = {
    "criticality": 2,
    "owner": "Unknown",
    "business_unit": "Unknown",
    "exposure": "unknown",
}


class AssetInventory:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or CONFIG_DIR / "assets.yaml"
        payload = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        self.assets = payload.get("assets", {})

    def enrich(self, events: pd.DataFrame) -> pd.DataFrame:
        enriched = events.copy()
        enriched["asset_criticality"] = enriched["asset"].map(lambda asset: self._asset_value(asset, "criticality")).astype(int)
        enriched["asset_owner"] = enriched["asset"].map(lambda asset: self._asset_value(asset, "owner"))
        enriched["business_unit"] = enriched["asset"].map(lambda asset: self._asset_value(asset, "business_unit"))
        enriched["asset_exposure"] = enriched["asset"].map(lambda asset: self._asset_value(asset, "exposure"))
        return enriched

    def _asset_value(self, asset: str, field: str) -> object:
        return self.assets.get(str(asset), DEFAULT_ASSET).get(field, DEFAULT_ASSET[field])
