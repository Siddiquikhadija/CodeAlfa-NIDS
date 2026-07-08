#!/usr/bin/env python3
"""
NIDS Live Dashboard — Streamlit
--------------------------------
Reads Suricata's eve.json (alerts) and the response engine's incidents.log
(actions taken) and renders a live security dashboard: KPIs, alert volume
over time, top signatures, top source IPs, severity breakdown, a filterable
alert table, and a table of currently-active auto-blocks.

Run:
    pip install streamlit pandas plotly
    streamlit run app.py

No live Suricata yet? Tick "Demo mode" in the sidebar to explore the
dashboard with synthetic sample data before wiring it up to real logs.
"""

import json
import random
import time
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# --------------------------------------------------------------------------
# Page config
# --------------------------------------------------------------------------
st.set_page_config(
    page_title="NIDS Dashboard",
    page_icon="🛡️",
    layout="wide",
)

SEVERITY_LABELS = {1: "High", 2: "Medium", 3: "Low"}
SEVERITY_COLORS = {"High": "#e03131", "Medium": "#f08c00", "Low": "#2f9e44"}

# --------------------------------------------------------------------------
# Sidebar — configuration
# --------------------------------------------------------------------------
st.sidebar.title("🛡️ NIDS Dashboard")

demo_mode = st.sidebar.checkbox(
    "Demo mode (synthetic sample data)",
    value=True,
    help="Turn off once eve.json / incidents.log exist on this host.",
)

eve_path = st.sidebar.text_input("eve.json path", "/var/log/suricata/eve.json")
incident_path = st.sidebar.text_input(
    "incidents.log path", "/var/log/suricata/incidents.log"
)

max_lines = st.sidebar.slider(
    "Max recent alerts to load", 100, 20000, 3000, step=100
)

auto_refresh = st.sidebar.checkbox("Auto-refresh", value=False)
refresh_secs = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 10)

st.sidebar.caption(
    "Demo mode generates fake alerts locally — nothing is sent anywhere. "
    "Turn it off to point at a real Suricata deployment."
)

# --------------------------------------------------------------------------
# Data loading
# --------------------------------------------------------------------------
SIGNATURES = [
    "ET SCAN Potential SSH Scan",
    "ET POLICY Suspicious inbound to mySQL port",
    "ET WEB_SERVER SQL Injection Attempt",
    "ET WEB_SERVER Cross Site Scripting Attempt",
    "ET TROJAN Possible C2 Beacon",
    "ET SCAN Nmap Scripting Engine",
    "ET POLICY Excessive 404 errors possible web app scan",
    "ET DOS Possible SYN Flood",
    "ET EXFIL Large outbound data transfer",
]


def _random_ip(private: bool = False) -> str:
    if private:
        return f"192.168.1.{random.randint(2, 250)}"
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


@st.cache_data(ttl=5)
def load_demo_alerts(n: int = 400) -> pd.DataFrame:
    now = datetime.utcnow()
    rows = []
    for i in range(n):
        ts = now - timedelta(seconds=random.randint(0, 3600 * 6))
        sev = random.choices([1, 2, 3], weights=[1, 3, 6])[0]
        rows.append(
            {
                "time": ts,
                "src_ip": _random_ip(),
                "dest_ip": _random_ip(private=True),
                "signature": random.choice(SIGNATURES),
                "severity": sev,
            }
        )
    return pd.DataFrame(rows).sort_values("time", ascending=False)


@st.cache_data(ttl=5)
def load_demo_incidents(alerts: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, a in alerts.iterrows():
        action = {1: "BLOCKED for 30m", 2: "WARNED / RATE-LIMIT FLAG", 3: "LOGGED"}[
            a["severity"]
        ]
        rows.append(
            {
                "time": a["time"],
                "src_ip": a["src_ip"],
                "signature": a["signature"],
                "severity": a["severity"],
                "action_taken": action,
            }
        )
    return pd.DataFrame(rows)


def _tail_jsonl(path: str, max_lines: int):
    """Read up to the last `max_lines` JSON-lines from a file, tolerating
    partial/corrupt lines (e.g. a line being written mid-read)."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        with p.open("r", errors="ignore") as f:
            lines = f.readlines()[-max_lines:]
    except OSError:
        return []
    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


@st.cache_data(ttl=5)
def load_real_alerts(path: str, max_lines: int) -> pd.DataFrame:
    records = _tail_jsonl(path, max_lines)
    rows = []
    for ev in records:
        if ev.get("event_type") != "alert":
            continue
        alert = ev.get("alert", {})
        try:
            ts = pd.to_datetime(ev.get("timestamp"))
        except Exception:
            ts = pd.NaT
        rows.append(
            {
                "time": ts,
                "src_ip": ev.get("src_ip"),
                "dest_ip": ev.get("dest_ip"),
                "signature": alert.get("signature", "Unknown"),
                "severity": alert.get("severity", 3),
            }
        )
    if not rows:
        return pd.DataFrame(columns=["time", "src_ip", "dest_ip", "signature", "severity"])
    return pd.DataFrame(rows).sort_values("time", ascending=False)


@st.cache_data(ttl=5)
def load_real_incidents(path: str, max_lines: int) -> pd.DataFrame:
    records = _tail_jsonl(path, max_lines)
    if not records:
        return pd.DataFrame(
            columns=["time", "src_ip", "signature", "severity", "action_taken"]
        )
    df = pd.DataFrame(records)
    if "time" in df.columns:
        df["time"] = pd.to_datetime(df["time"], errors="coerce")
    return df.sort_values("time", ascending=False)


# --------------------------------------------------------------------------
# Load data
# --------------------------------------------------------------------------
if demo_mode:
    alerts_df = load_demo_alerts()
    incidents_df = load_demo_incidents(alerts_df)
    st.sidebar.info("Showing synthetic demo data.")
else:
    alerts_df = load_real_alerts(eve_path, max_lines)
    incidents_df = load_real_incidents(incident_path, max_lines)
    if alerts_df.empty:
        st.sidebar.warning(f"No alerts found yet at:\n{eve_path}")

alerts_df = alerts_df.dropna(subset=["time"]) if not alerts_df.empty else alerts_df
if not alerts_df.empty:
    alerts_df["severity_label"] = alerts_df["severity"].map(SEVERITY_LABELS).fillna("Low")

# --------------------------------------------------------------------------
# KPI row
# --------------------------------------------------------------------------
st.title("Network Intrusion Detection — Live Dashboard")

col1, col2, col3, col4 = st.columns(4)
total_alerts = len(alerts_df)
high_count = int((alerts_df["severity"] == 1).sum()) if not alerts_df.empty else 0
med_count = int((alerts_df["severity"] == 2).sum()) if not alerts_df.empty else 0
active_blocks = (
    int((incidents_df["action_taken"].astype(str).str.startswith("BLOCKED")).sum())
    if not incidents_df.empty and "action_taken" in incidents_df.columns
    else 0
)

col1.metric("Total alerts (loaded window)", f"{total_alerts:,}")
col2.metric("High severity", high_count)
col3.metric("Medium severity", med_count)
col4.metric("Auto-block actions", active_blocks)

st.divider()

# --------------------------------------------------------------------------
# Charts
# --------------------------------------------------------------------------
if alerts_df.empty:
    st.info(
        "No alert data to display yet. Enable Demo mode in the sidebar, "
        "or point the paths at a live eve.json / incidents.log."
    )
else:
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Alert volume over time")
        ts = (
            alerts_df.set_index("time")
            .resample("5min")
            .size()
            .reset_index(name="count")
        )
        fig = px.line(ts, x="time", y="count")
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with chart_col2:
        st.subheader("Severity breakdown")
        sev_counts = alerts_df["severity_label"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        fig = px.pie(
            sev_counts,
            names="severity",
            values="count",
            color="severity",
            color_discrete_map=SEVERITY_COLORS,
            hole=0.45,
        )
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)

    chart_col3, chart_col4 = st.columns(2)

    with chart_col3:
        st.subheader("Top signatures")
        top_sigs = alerts_df["signature"].value_counts().head(10).reset_index()
        top_sigs.columns = ["signature", "count"]
        fig = px.bar(top_sigs, x="count", y="signature", orientation="h")
        fig.update_layout(
            height=350,
            margin=dict(l=10, r=10, t=10, b=10),
            yaxis={"categoryorder": "total ascending"},
        )
        st.plotly_chart(fig, use_container_width=True)

    with chart_col4:
        st.subheader("Top source IPs")
        top_ips = alerts_df["src_ip"].value_counts().head(10).reset_index()
        top_ips.columns = ["src_ip", "count"]
        fig = px.bar(top_ips, x="count", y="src_ip", orientation="h")
        fig.update_layout(
            height=350,
            margin=dict(l=10, r=10, t=10, b=10),
            yaxis={"categoryorder": "total ascending"},
        )
        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # ----------------------------------------------------------------
    # Filterable alert table
    # ----------------------------------------------------------------
    st.subheader("Recent alerts")
    f1, f2, f3 = st.columns([1, 1, 2])
    with f1:
        sev_filter = st.multiselect(
            "Severity", ["High", "Medium", "Low"], default=["High", "Medium", "Low"]
        )
    with f2:
        ip_filter = st.text_input("Filter by source IP contains")
    with f3:
        sig_filter = st.text_input("Filter by signature contains")

    filtered = alerts_df[alerts_df["severity_label"].isin(sev_filter)]
    if ip_filter:
        filtered = filtered[filtered["src_ip"].astype(str).str.contains(ip_filter, na=False)]
    if sig_filter:
        filtered = filtered[
            filtered["signature"].astype(str).str.contains(sig_filter, case=False, na=False)
        ]

    st.dataframe(
        filtered[["time", "src_ip", "dest_ip", "signature", "severity_label"]].head(500),
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    # ----------------------------------------------------------------
    # Response engine actions
    # ----------------------------------------------------------------
    st.subheader("Response engine actions")
    if incidents_df.empty:
        st.caption("No entries in incidents.log yet.")
    else:
        st.dataframe(
            incidents_df.head(300),
            use_container_width=True,
            hide_index=True,
        )

# --------------------------------------------------------------------------
# Auto-refresh
# --------------------------------------------------------------------------
if auto_refresh:
    time.sleep(refresh_secs)
    st.rerun()
