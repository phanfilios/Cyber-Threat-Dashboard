from __future__ import annotations

from datetime import UTC, datetime

from src.data_collection.collector import ThreatDataCollector
from src.detection.detector import ThreatDetector
from src.enrichment.pipeline import EnrichmentPipeline
from src.processing.analyzer import ThreatAnalyzer
from src.processing.parser import EventParser
from src.processing.preprocess import preprocess_events
from src.utils.helpers import PROCESSED_DATA_DIR, REPORTS_DIR, ensure_project_dirs


def build_scored_events():
    raw_events = ThreatDataCollector().load_all()
    if raw_events.empty:
        raise RuntimeError("No raw CSV feeds found in data/raw.")

    parsed = EventParser().parse(raw_events)
    processed = preprocess_events(parsed)
    enriched = EnrichmentPipeline().enrich(processed)
    return ThreatDetector().score(enriched)


def write_report(scored_events) -> str:
    analyzer = ThreatAnalyzer()
    summary = analyzer.summarize(scored_events)
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    top_incidents = scored_events.head(5)

    lines = [
        "# Cyber Threat Summary",
        "",
        f"Generated: {generated_at}",
        "",
        "## Executive Snapshot",
        "",
        f"- Total events: {summary['total_events']}",
        f"- Critical events: {summary['critical_events']}",
        f"- Unique sources: {summary['unique_sources']}",
        f"- Most affected asset: {summary['top_asset']}",
        f"- Most common signal: {summary['top_event_type']}",
        "",
        "## Top Incidents",
        "",
    ]

    for _, incident in top_incidents.iterrows():
        lines.append(
            f"- {incident['risk_level']} ({incident['risk_score']}): "
            f"{incident['rule_name']} on {incident['asset']} from {incident['source_ip']} "
            f"[{incident['mitre_technique']}]"
        )
        lines.append(f"  Recommendation: {incident['recommendation']}")

    report = "\n".join(lines) + "\n"
    report_path = REPORTS_DIR / "threat_summary.md"
    report_path.write_text(report, encoding="utf-8")
    return str(report_path)


def main() -> None:
    ensure_project_dirs()
    scored_events = build_scored_events()
    output_path = PROCESSED_DATA_DIR / "events_scored.csv"
    scored_events.to_csv(output_path, index=False)
    report_path = write_report(scored_events)

    print(f"Scored events written to {output_path}")
    print(f"Report written to {report_path}")


if __name__ == "__main__":
    main()
