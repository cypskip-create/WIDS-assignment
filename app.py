"""Run with: python -m streamlit run app.py"""
import os
from pathlib import Path
import streamlit as st
from wids.cli import setup_logging
from wids.storage import Storage
from wids.monitoring import Monitor
from dashboard.views import overview, monitor, attacks, analytics, incidents, settings_page, stylesheet

st.set_page_config(page_title="SentinelWiFi | Wireless Defense", page_icon="◈", layout="wide")
setup_logging()
stylesheet()


@st.cache_resource
def runtime(db_path):
    storage = Storage(db_path)
    # Recovery after a process crash: never pretend an abandoned capture is live.
    storage.execute("UPDATE sessions SET status='interrupted',ended=strftime('%s','now'),error='Application process restarted' WHERE status IN ('running','paused')")
    storage.prune(storage.get_settings().retention_days)
    return storage, Monitor(storage)


store, worker = runtime(os.environ.get("SENTINEL_DB", "data/sentinel.sqlite3"))
preferences = store.get_settings()
with st.sidebar:
    st.markdown('<div class="brand">◈ <span>Sentinel<span style="color:#36d6df">WiFi</span></span></div><p class="subbrand">WIRELESS DEFENSE PLATFORM</p>', unsafe_allow_html=True)
    page = st.radio("Workspace", ["Security Overview", "Wireless Traffic Monitor", "Attack Detection", "Machine Learning Analytics", "Security Incidents", "Settings"], label_visibility="collapsed")
    st.divider()
    st.caption("LOCAL • PASSIVE INSPECTION")
    st.caption("Intelligent Wireless Intrusion Detection and Monitoring")
    st.caption("Observed MAC addresses can be spoofed. No active countermeasures are enabled.")

st.caption("SECURITY OPERATIONS / "+page.upper())
st.title(page)
st.markdown({"Security Overview": "Your wireless environment, grounded in observed traffic.", "Wireless Traffic Monitor": "Replay recorded frames or inspect an authorized monitor-mode interface.", "Attack Detection": "Understand the observations behind every detection.", "Machine Learning Analytics": "Reproducible training. Measured performance. Explicit limitations.", "Security Incidents": "Investigate, document, and resolve detection events.", "Settings": "Tune the detector to your authorized environment."}[page])


@st.fragment(run_every=preferences.refresh_seconds)
def content():
    worker.touch()
    routes = {"Security Overview": overview, "Wireless Traffic Monitor": monitor, "Attack Detection": attacks,
              "Machine Learning Analytics": analytics, "Security Incidents": incidents, "Settings": settings_page}
    try:
        routes[page](store, worker)
    except (ValueError, OSError, RuntimeError) as error:
        st.error(str(error))


content()
