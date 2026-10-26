from dataclasses import replace
import hashlib
import json
from pathlib import Path
import time
import pandas as pd
import plotly.express as px
import streamlit as st
from wids.capture import available_interfaces
from wids.config import Settings
from wids.feature_extractor import FEATURES
from wids.fixture import generate_fixture
from wids.storage import csv_export

COLORS = {"Normal": "#36c89b", "Malicious": "#f16d7a", "rule": "#f4b74d", "ml": "#42c4dd", "both": "#bb94f7", "none": "#36c89b"}


def stylesheet():
    st.markdown('''<style>
    .stApp { background:radial-gradient(ellipse at 90% 0%,#102039 0%,#080e1a 56%); }
    [data-testid="stSidebar"] { background:#0b1422;border-right:1px solid #213048; }
    .block-container { padding-top:2.2rem;padding-bottom:3rem;max-width:1600px; }
    h1 {font-weight:650!important;letter-spacing:-1.2px;font-size:2.35rem!important;}
    h3 {font-size:1.1rem!important;letter-spacing:-.1px;}
    [data-testid="stMetric"] {background:#111c2e;border:1px solid #23324b;border-radius:12px;padding:18px 20px;}
    [data-testid="stMetricLabel"] {color:#9bacc4;font-size:.8rem;}
    [data-testid="stMetricValue"] {font-size:2rem;font-weight:600;}
    .brand {display:flex;gap:10px;align-items:center;color:#36d6df;font-size:1.65rem;font-weight:700;margin-top:8px;}
    .brand>span {color:#edf3fb;letter-spacing:-.8px;}
    .subbrand {font-size:.61rem;letter-spacing:2px;color:#788da9;margin:5px 0 32px 0;}
    [data-testid="stSidebar"] label {font-size:.9rem;}
    .stButton>button {border-radius:8px;}
    </style>''', unsafe_allow_html=True)


def chart(fig):
    fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(color="#a6b7ce", family="Arial"), margin=dict(l=12, r=16, t=30, b=15), height=300,
                      legend_title_text="", xaxis=dict(gridcolor="#203047"), yaxis=dict(gridcolor="#203047"))
    st.plotly_chart(fig, use_container_width=True)


def observation_data(store, session=None, since=None):
    query = "SELECT o.* FROM observations o JOIN sessions s ON s.id=o.session_id WHERE 1=1"
    params = []
    if session:
        query += " AND o.session_id=?"
        params.append(session)
    if since is not None:
        query += " AND s.started>=?"
        params.append(since)
    query += " ORDER BY o.id DESC LIMIT 5000"
    rows = store.rows(query, params)
    if not rows:
        return pd.DataFrame()
    frame = pd.DataFrame([{**r, **json.loads(r["features"])} for r in rows])
    frame["capture_time"] = pd.to_datetime(frame.timestamp, unit="s", utc=True)
    return frame.sort_values("timestamp")


def session_select(store, key):
    sessions = store.rows("SELECT * FROM sessions ORDER BY started DESC LIMIT 100")
    if not sessions:
        st.info("No traffic has been ingested. Open Wireless Traffic Monitor to start a PCAP replay.")
        return None
    options = {row["id"]: f"{Path(row['source']).name} · {row['provenance']} · {row['id'][:8]}" for row in sessions}
    return st.selectbox("Monitoring session", list(options), format_func=options.get, key=key)


def overview(store, worker):
    cols = st.columns([2, 1])
    with cols[0]:
        st.caption(f"ENGINE: {worker.status.upper()}  /  {worker.snapshot()['model_status']}")
    with cols[1]:
        period = st.selectbox("Reporting period", ["Last 24 hours", "Last 7 days", "All sessions"], label_visibility="collapsed")
    since = time.time()-({"Last 24 hours": 86400, "Last 7 days": 604800}.get(period, time.time()))
    sessions = store.rows("SELECT * FROM sessions WHERE started>=? ORDER BY started DESC", (since,))
    data = observation_data(store, since=since)
    alerts = store.rows("SELECT i.* FROM incidents i JOIN sessions s ON s.id=i.session_id WHERE s.started>=? ORDER BY i.timestamp DESC", (since,))
    suspicious = store.rows("SELECT COUNT(*) AS n FROM observations o JOIN sessions s ON s.id=o.session_id WHERE s.started>=? AND o.source!='none'", (since,))[0]["n"]
    total = sum(s["frames"] for s in sessions)
    active = sum(a["status"] != "Resolved" for a in alerts)
    columns = st.columns(4)
    for col, label, value in zip(columns, ["Frames processed", "Suspicious observations", "Flood alerts", "Active incidents"], [f"{total:,}", f"{suspicious:,}", sum(a["category"] == "Deauthentication flood" for a in alerts), active]):
        col.metric(label, value)
    st.caption("Period uses ingestion time. Charts use capture time (UTC). Rolling observations overlap; they are not independent packets. Charts show up to 5,000 latest observations.")
    left, right = st.columns([2, 1])
    with left:
        with st.container(border=True):
            st.subheader("Traffic activity")
            if data.empty:
                st.info("Awaiting traffic. Start the supplied synthetic replay to verify detection.")
            else:
                chart_sid = st.selectbox("Chart session", list(dict.fromkeys(data.session_id)), format_func=lambda sid: sid[:8])
                chart_data = data[data.session_id == chart_sid]
                grouped = chart_data.groupby("capture_time")[["frames_per_second", "deauth_per_second"]].sum().reset_index()
                chart(px.line(grouped, x="capture_time", y=["frames_per_second", "deauth_per_second"], color_discrete_sequence=["#36d6df", "#f4b74d"], labels={"value": "Frames / second", "capture_time": "Capture time (UTC)", "variable": "Traffic"}))
    with right:
        with st.container(border=True):
            st.subheader("Detection sources")
            if not data.empty:
                counts = data.source.map({"none": "No alert signal", "rule": "Rule", "ml": "ML", "both": "Both"}).value_counts().rename_axis("result").reset_index(name="count")
                chart(px.pie(counts, values="count", names="result", hole=.73, color_discrete_sequence=["#36c89b", "#f4b74d", "#42c4dd", "#bb94f7"]))
            else:
                st.caption("No observations yet")
    st.subheader("Latest security events")
    if alerts:
        st.warning(alerts[0]["category"]+" — "+alerts[0]["explanation"])
        st.dataframe(pd.DataFrame(alerts)[["timestamp", "category", "severity", "source", "transmitter", "status"]].head(8), hide_index=True, use_container_width=True)
    else:
        st.success("No incidents recorded in this reporting period.")
    if sessions:
        st.caption(f"Latest source: {sessions[0]['source']} | Provenance: {sessions[0]['provenance']}")
        st.dataframe(pd.DataFrame(sessions)[["id", "source", "provenance", "status", "frames", "skipped"]].head(8), hide_index=True, use_container_width=True)


def monitor(store, worker):
    settings = store.get_settings()
    state = worker.snapshot()
    left, right = st.columns([2, 1])
    with left:
        mode = st.radio("Traffic source", ["Synthetic PCAP demo", "Recorded PCAP", "Live wireless capture"], horizontal=True, disabled=state["active"])
        source, provenance = None, "user capture"
        if mode == "Synthetic PCAP demo":
            source = Path("data/demo/synthetic_deauth.pcap")
            if not source.exists():
                generate_fixture(source)
            provenance = "synthetic"
            st.info("SYNTHETIC TEST DATA · Valid 802.11 frames, generated locally and never transmitted. Demonstrates software behavior, not real-world ML performance.")
        elif mode == "Recorded PCAP":
            uploaded = st.file_uploader("Upload raw IEEE 802.11 PCAP / PCAPNG", type=["pcap", "pcapng", "cap"], disabled=state["active"])
            if uploaded:
                payload = uploaded.getvalue()
                source = Path("data/uploads")/(hashlib.sha256(payload).hexdigest()+".pcap")
                source.parent.mkdir(parents=True, exist_ok=True)
                if not source.exists():
                    source.write_bytes(payload)
            local = st.text_input("Or local PCAP path", disabled=state["active"])
            if local.strip():
                source = Path(local.strip())
            provenance = st.selectbox("Capture provenance", ["user capture", "genuine research capture", "synthetic"], disabled=state["active"])
            st.caption("Ethernet-only captures are rejected for wireless deauthentication analysis.")
        else:
            interfaces, explanation = available_interfaces()
            st.info(explanation)
            if interfaces:
                source = st.selectbox("Monitor-mode interface", interfaces, disabled=state["active"])
                authorized = st.checkbox("I am authorized to passively capture this network", disabled=state["active"])
                if not authorized:
                    source = None
            provenance = "authorized live capture"
        buttons = st.columns(4)
        if buttons[0].button("Start / Restart", type="primary", disabled=state["active"] or source is None, use_container_width=True):
            store.prune(settings.retention_days)
            worker.start(settings, str(source), "live" if mode == "Live wireless capture" else "replay", provenance, lease=True)
            st.rerun(scope="fragment")
        if buttons[1].button("Pause", disabled=not state["active"] or mode == "Live wireless capture", use_container_width=True):
            worker.pause()
        if buttons[2].button("Resume", disabled=state["status"] != "paused", use_container_width=True):
            worker.resume()
        if buttons[3].button("Stop", disabled=not state["active"], use_container_width=True):
            worker.stop()
        st.caption(f"Replay: {settings.replay_speed:g}× · Window: {settings.window_seconds:g}s · Rule: ≥{settings.deauth_threshold:g} deauth/s · Cooldown: {settings.cooldown_seconds:g}s")
    with right:
        with st.container(border=True):
            st.subheader("Capture engine")
            st.metric("Status", worker.status.upper())
            st.caption(worker.snapshot()["model_status"])
            st.caption("A browser heartbeat stops capture within 30 seconds after all dashboard tabs close. Restart begins a new session; prior evidence remains.")
            if worker.error:
                st.error(worker.error)
    if state["session_id"]:
        session = store.rows("SELECT * FROM sessions WHERE id=?", (state["session_id"],))[0]
        cols = st.columns(3)
        cols[0].metric("802.11 frames", session["frames"])
        cols[1].metric("Skipped / non-wireless", session["skipped"])
        data = observation_data(store, state["session_id"])
        rate = data[data.timestamp == data.timestamp.max()].frames_per_second.sum() if not data.empty else 0
        cols[2].metric("Latest window rate", f"{rate:.1f} fps")
        alerts = store.rows("SELECT * FROM incidents WHERE session_id=? ORDER BY timestamp DESC", (state["session_id"],))
        if alerts:
            st.warning("DETECTION · "+alerts[0]["explanation"])
    st.subheader("Recent frame metadata")
    st.caption("At most 100 recent frames retained in memory. Payloads are not stored by the pipeline.")
    if state["recent"]:
        st.dataframe(pd.DataFrame(state["recent"]), hide_index=True, use_container_width=True)
    else:
        st.caption("Waiting for input")


def attacks(store, worker):
    sid = session_select(store, "attack_session")
    if sid is None:
        return
    data = observation_data(store, sid)
    if data.empty:
        st.info("Waiting for observation windows")
        return
    cols = st.columns(2)
    with cols[0]:
        st.subheader("Deauthentication rate")
        chart(px.line(data, x="capture_time", y="deauth_per_second", color="transmitter", labels={"deauth_per_second": "Deauth / second", "capture_time": "Capture time (UTC)"}))
    with cols[1]:
        st.subheader("Observed transmitter / BSSID")
        st.dataframe(data.groupby(["transmitter", "bssid"], dropna=False).agg(peak_deauth_fps=("deauth_per_second", "max"), suspicious_windows=("rule_fired", "sum")).reset_index(), hide_index=True)
        st.caption("MACs can be spoofed. Peak rates are measured per transmitter / BSSID. Counts refer to overlapping windows.")
    st.subheader("Detection evidence")
    st.dataframe(data[["capture_time", "transmitter", "deauth_count", "deauth_per_second", "rule_fired", "ml_prediction", "confidence", "source"]], hide_index=True, use_container_width=True)
    st.caption("Confidence is P(malicious), an uncalibrated Random Forest vote probability. A binary model does not identify attack categories. Rule / ML disagreements are retained.")
    for row in store.rows("SELECT * FROM incidents WHERE session_id=? ORDER BY timestamp DESC LIMIT 10", (sid,)):
        with st.expander(f"{row['severity']} · {row['category']} · {row['source']}"):
            st.write(row["explanation"])
            st.json(json.loads(row["evidence"]))


def analytics(store, worker):
    model_path = Path(store.get_settings().model_path)
    meta_path = Path(str(model_path)+".json")
    if meta_path.exists():
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        st.caption(f"{metadata['algorithm']} · {metadata['source']} · {metadata['provenance'].upper()}")
        if metadata["provenance"] != "genuine":
            st.warning("Synthetic model evaluation: software test only; not real-world detection evidence.")
        cols = st.columns(4)
        for col, key in zip(cols, ["accuracy", "precision", "recall", "f1"]):
            col.metric(key.replace("_", " ").title(), f"{metadata['metrics'][key]:.2%}")
        st.warning(metadata.get("limitations", "Generalization beyond the evaluated capture has not been established."))
        st.caption(f"Training: {metadata['train_samples']:,} windows · Test: {metadata['test_samples']:,} windows · {metadata['evaluation_method']}")
        left, right = st.columns(2)
        with left:
            st.subheader("Held-out confusion matrix")
            chart(px.imshow(metadata["metrics"]["confusion_matrix"], x=["Normal", "Malicious"], y=["Normal", "Malicious"], text_auto=True, color_continuous_scale="Teal", labels={"x": "Predicted", "y": "Actual", "color": "Windows"}))
        with right:
            st.subheader("Fitted feature importance")
            importance = pd.Series(metadata["feature_importance"]).sort_values().tail(10).rename_axis("Feature").reset_index(name="Importance")
            chart(px.bar(importance, x="Importance", y="Feature", orientation="h", color_discrete_sequence=["#36d6df"]))
        left, right = st.columns(2)
        with left:
            st.subheader("Class distribution")
            dist = metadata["class_distribution"]
            chart(px.bar(x=["Normal", "Malicious"], y=[dist.get("0", 0), dist.get("1", 0)], labels={"x": "Ground truth", "y": "Windows"}, color_discrete_sequence=["#36d6df"]))
        with right:
            st.subheader("Actual vs predicted")
            predictions = Path("reports/predictions.csv")
            if predictions.exists():
                st.dataframe(pd.read_csv(predictions).head(100), hide_index=True, use_container_width=True)
        with st.expander("Model metadata and evaluation logs"):
            st.json(metadata)
        st.download_button("Download evaluation JSON", json.dumps(metadata, indent=2), "evaluation.json", "application/json")
    else:
        st.info("No model trained. Rule-based monitoring remains available. Import genuine labeled packet CSVs, prepare canonical windows, then train explicitly.")
    with st.expander("Dataset inspection and preparation"):
        st.caption("Supported CSV adapter: explicit Wireshark packet fields and Label. AWID3 is inspected before conversion; AWID2 headerless files need a separate reviewed adapter. No arbitrary CSV column is fed to packet inference.")
        upload = st.file_uploader("Inspect labeled packet CSV", type=["csv"])
        if upload:
            from wids.dataset import inspect_csv
            data = upload.getvalue()
            local = Path("data/uploads")/(hashlib.sha256(data).hexdigest()+".csv")
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(data)
            inspection = inspect_csv(local)
            st.write({"columns": inspection["columns"], "missing_required": inspection["missing_required"]})
            st.dataframe(pd.DataFrame(inspection["sample"]).astype(str), hide_index=True)
        st.caption("To prepare the downloaded public subset, run: python -m scripts.prepare_dataset")
        source_dir = st.text_input("Labeled CSV folder (one recording, capture order)", "data/raw/wpa3")
        source_name = st.text_input("Dataset citation / source", "The WPA3 Dataset - hsngccu/WPA3-dataset, MIT")
        provenance = st.selectbox("Training data provenance", ["genuine", "synthetic"])
        if st.button("Prepare canonical windows", disabled=worker.active):
            import re
            from wids.dataset import prepare_csv
            paths = sorted(Path(source_dir).glob("*.csv"), key=lambda p: [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", p.name)])
            if not paths:
                raise ValueError("No CSV files found")
            with st.spinner("Streaming packet CSVs into canonical windows…"):
                result = prepare_csv(paths, settings=store.get_settings(), source=source_name, provenance=provenance)
            st.success(f"Prepared {result['windows']} windows")
    with st.expander("Train Random Forest"):
        prepared = st.text_input("Prepared feature CSV", "data/processed/windows.csv")
        st.caption("Fixed seed 42; train-only imputation; group-disjoint holdout. Only trusted local model artifacts are loaded. Training is never triggered by refresh.")
        if st.button("Train and evaluate", type="primary", disabled=worker.active):
            from wids.training import train
            with st.spinner("Training and evaluating held-out observations…"):
                result = train(prepared, str(model_path))
            store.execute("INSERT INTO models(timestamp,path,metadata) VALUES(?,?,?)", (time.time(), str(model_path), json.dumps(result)))
            store.event(None, "training", json.dumps(result["metrics"]))
            st.success("Training complete; evaluation saved to reports/evaluation.json")
            st.rerun(scope="fragment")


def incidents(store, worker):
    rows = store.rows("SELECT i.*,s.provenance FROM incidents i JOIN sessions s ON s.id=i.session_id ORDER BY i.timestamp DESC")
    if not rows:
        st.info("No incidents yet. Replay the synthetic fixture to exercise the complete detection path.")
        return
    cols = st.columns(4)
    severity = cols[0].multiselect("Severity", ["Low", "Medium", "High", "Critical"])
    source = cols[1].multiselect("Detection source", ["rule", "ml", "both"])
    status = cols[2].multiselect("Status", ["New", "Investigating", "Resolved"])
    search = cols[3].text_input("Search evidence / MAC")
    filtered = [row for row in rows if (not severity or row["severity"] in severity) and (not source or row["source"] in source) and (not status or row["status"] in status) and (not search or search.lower() in json.dumps(row).lower())]
    st.dataframe(pd.DataFrame(filtered)[["id", "timestamp", "category", "severity", "source", "transmitter", "status", "provenance"]] if filtered else pd.DataFrame(), hide_index=True, use_container_width=True)
    st.download_button("Export filtered incidents CSV", csv_export(filtered), "incidents.csv", "text/csv")
    if filtered:
        selected = st.selectbox("Inspect incident", [row["id"] for row in filtered])
        incident = next(row for row in filtered if row["id"] == selected)
        st.warning(incident["explanation"])
        st.json(incident)
        target = st.selectbox("Update status", ["New", "Investigating", "Resolved"], index=["New", "Investigating", "Resolved"].index(incident["status"]))
        if st.button("Save incident status"):
            store.update_status(selected, target)
            st.rerun(scope="fragment")


def settings_page(store, worker):
    current = store.get_settings()
    with st.form("settings"):
        left, right = st.columns(2)
        with left:
            window = st.number_input("Observation window (seconds)", min_value=1.0, max_value=120.0, value=float(current.window_seconds))
            step = st.number_input("Observation step (seconds)", min_value=0.1, max_value=120.0, value=float(current.step_seconds))
            threshold = st.number_input("Deauthentication threshold (frames / second)", min_value=0.1, value=float(current.deauth_threshold))
            cooldown = st.number_input("Alert cooldown (seconds)", min_value=0.0, value=float(current.cooldown_seconds))
            critical = st.number_input("Critical severity threshold multiplier", min_value=1.0, value=float(current.critical_multiplier))
        with right:
            speed = st.number_input("Replay speed multiplier", min_value=0.1, max_value=1000.0, value=float(current.replay_speed))
            refresh = st.number_input("Display refresh (seconds)", min_value=0.5, max_value=30.0, value=float(current.refresh_seconds))
            retention = st.number_input("Local session retention (days)", min_value=1, max_value=3650, value=current.retention_days)
            models = [str(p).replace("\\", "/") for p in Path("models").glob("*.joblib")]
            options = sorted(set([current.model_path]+models))
            model = st.selectbox("Trusted local model", options, index=options.index(current.model_path))
            interface = st.text_input("Preferred monitoring interface", current.interface)
        st.caption("Thresholds are illustrative and require site-specific tuning. High = rate rule; Critical = multiplier × threshold; Medium = ML only. Changing window or step disables incompatible ML models until retrained. Saved settings apply to new sessions.")
        if st.form_submit_button("Save settings", disabled=worker.active):
            updated = replace(current, window_seconds=window, step_seconds=step, deauth_threshold=threshold, cooldown_seconds=cooldown, critical_multiplier=critical, replay_speed=speed, refresh_seconds=refresh, retention_days=int(retention), model_path=model, interface=interface)
            store.save_settings(updated)
            st.success("Preferences saved. Reload the page to apply the display refresh interval.")
    st.subheader("Local evidence management")
    st.caption("Retention deletes completed sessions and their evidence when starting capture or application startup. Raw uploads and downloaded datasets require manual deletion. Running sessions are retained.")
    if st.button("Export monitoring report"):
        from wids.reporting import export_report
        st.success(f"Exported actual SQLite data to {export_report(store)}")
    confirm = st.checkbox("Clear completed synthetic sessions and their incidents")
    if st.button("Clear synthetic demo history", disabled=not confirm or worker.active):
        store.clear_synthetic()
        st.success("Completed synthetic session history cleared")
