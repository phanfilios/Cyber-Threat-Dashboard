from __future__ import annotations

import sys
from pathlib import Path

import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data_collection.collector import ThreatDataCollector
from src.detection.detector import ThreatDetector
from src.enrichment.pipeline import EnrichmentPipeline
from src.processing.analyzer import ThreatAnalyzer
from src.processing.parser import EventParser
from src.processing.preprocess import preprocess_events


st.set_page_config(
    page_title="Cyber Threat Dashboard",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_data(show_spinner=False)
def load_events():
    collector = ThreatDataCollector()
    raw = collector.load_all()
    if raw.empty:
        return raw
    parsed = EventParser().parse(raw)
    processed = preprocess_events(parsed)
    enriched = EnrichmentPipeline().enrich(processed)
    return ThreatDetector().score(enriched)


def risk_palette():
    return {
        "Low": "#38bdf8",
        "Medium": "#f59e0b",
        "High": "#ef4444",
        "Critical": "#b91c1c",
    }


events = load_events()
analyzer = ThreatAnalyzer()

st.markdown(
    """
    <style>
    .stApp {
        background:
            radial-gradient(circle at 18% 18%, rgba(20, 184, 166, 0.16), transparent 30%),
            linear-gradient(135deg, #07111f 0%, #101827 45%, #0b1120 100%);
        color: #e5eefb;
    }
    [data-testid="stSidebar"] {
        background: #08111f;
        border-right: 1px solid rgba(148, 163, 184, 0.18);
    }
    [data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.72);
        border: 1px solid rgba(148, 163, 184, 0.20);
        border-radius: 8px;
        padding: 16px;
    }
    div[data-testid="stDataFrame"] {
        border: 1px solid rgba(148, 163, 184, 0.22);
        border-radius: 8px;
        overflow: hidden;
    }
    h1, h2, h3 {
        letter-spacing: 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("Cyber Threat Dashboard")
st.caption("Operational visibility for signals, detections, and risk across your environment.")

if events.empty:
    st.warning("No CSV feeds found in data/raw. Add event files using the documented schema.")
    st.stop()

with st.sidebar:
    st.header("Filters")
    risk_levels = st.multiselect(
        "Risk level",
        options=["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"],
    )
    assets = st.multiselect("Assets", options=sorted(events["asset"].unique()))
    countries = st.multiselect("Countries", options=sorted(events["country"].unique()))
    tactics = st.multiselect("MITRE tactics", options=sorted(events["mitre_tactic"].unique()))
    minimum_score = st.slider("Minimum risk score", 0, 100, 0)

filtered = events[events["risk_level"].isin(risk_levels) & (events["risk_score"] >= minimum_score)]
if assets:
    filtered = filtered[filtered["asset"].isin(assets)]
if countries:
    filtered = filtered[filtered["country"].isin(countries)]
if tactics:
    filtered = filtered[filtered["mitre_tactic"].isin(tactics)]

summary = analyzer.summarize(filtered)

metric_cols = st.columns(5)
metric_cols[0].metric("Events", summary["total_events"])
metric_cols[1].metric("Critical", summary["critical_events"])
metric_cols[2].metric("Sources", summary["unique_sources"])
metric_cols[3].metric("Top Asset", summary["top_asset"])
metric_cols[4].metric("Top Signal", summary["top_event_type"])

left, right = st.columns([1.25, 1])

with left:
    st.subheader("Threat Timeline")
    timeline = analyzer.timeline(filtered)
    fig = px.area(
        timeline,
        x="timestamp",
        y="count",
        color_discrete_sequence=["#22d3ee"],
        template="plotly_dark",
    )
    fig.update_layout(height=360, margin=dict(l=10, r=10, t=20, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Risk Distribution")
    risk_counts = filtered.groupby("risk_level", as_index=False).size().rename(columns={"size": "count"})
    fig = px.bar(
        risk_counts,
        x="risk_level",
        y="count",
        color="risk_level",
        color_discrete_map=risk_palette(),
        template="plotly_dark",
    )
    fig.update_layout(showlegend=False, height=360, margin=dict(l=10, r=10, t=20, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(fig, use_container_width=True)

st.subheader("Highest Priority Incidents")
incident_columns = [
    "timestamp",
    "risk_score",
    "risk_level",
    "rule_name",
    "mitre_tactic",
    "mitre_technique",
    "event_type",
    "severity",
    "reputation_label",
    "asset_criticality",
    "source_ip",
    "destination_ip",
    "asset",
    "asset_owner",
    "country",
    "description",
    "recommendation",
]
st.dataframe(filtered[incident_columns].sort_values("risk_score", ascending=False), use_container_width=True, hide_index=True)

bottom_left, bottom_mid, bottom_right = st.columns(3)
with bottom_left:
    st.subheader("Signal Mix")
    signal_counts = analyzer.event_type_counts(filtered)
    fig = px.pie(signal_counts, names="event_type", values="count", hole=0.45, template="plotly_dark")
    fig.update_layout(height=330, margin=dict(l=10, r=10, t=20, b=10), paper_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(fig, use_container_width=True)

with bottom_mid:
    st.subheader("MITRE Tactics")
    tactic_counts = filtered.groupby("mitre_tactic", as_index=False).size().rename(columns={"size": "count"}).sort_values("count", ascending=False)
    fig = px.bar(tactic_counts, x="count", y="mitre_tactic", orientation="h", color="count", color_continuous_scale="Bluered", template="plotly_dark")
    fig.update_layout(height=330, margin=dict(l=10, r=10, t=20, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(fig, use_container_width=True)

with bottom_right:
    st.subheader("Source Countries")
    country_counts = filtered.groupby("country", as_index=False).size().rename(columns={"size": "count"}).sort_values("count", ascending=False)
    fig = px.bar(country_counts, x="count", y="country", orientation="h", color="count", color_continuous_scale="Tealrose", template="plotly_dark")
    fig.update_layout(height=330, margin=dict(l=10, r=10, t=20, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(fig, use_container_width=True)

st.subheader("Explainability")
explain_columns = ["risk_score", "rule_name", "asset", "risk_factors", "recommendation"]
st.dataframe(filtered[explain_columns].sort_values("risk_score", ascending=False).head(8), use_container_width=True, hide_index=True)
