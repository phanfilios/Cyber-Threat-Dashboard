from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
REPORTS_DIR = PROJECT_ROOT / "reports"


def ensure_project_dirs() -> None:
    """Create runtime directories that may not exist on a fresh checkout."""
    for path in (CONFIG_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, REPORTS_DIR):
        path.mkdir(parents=True, exist_ok=True)


def project_path(*parts: str) -> Path:
    return PROJECT_ROOT.joinpath(*parts)
