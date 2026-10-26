import json
from pathlib import Path
import time
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap
from wids.config import Settings
from wids.fixture import generate_fixture
from wids.monitoring import Monitor
from wids.replay import replay_sync
from wids.storage import Storage, csv_export
from wids.reporting import export_report


def test_full_pcap_pipeline_and_status(tmp_path):
    store = Storage(tmp_path/"test.sqlite3")
    path = generate_fixture(tmp_path/"test.pcap")
    sid = replay_sync(path, store, Settings(), "synthetic", model=False)
    session = store.rows("SELECT * FROM sessions WHERE id=?", (sid,))[0]
    assert session["frames"] == 1320 and session["status"] == "completed"
    incidents = store.rows("SELECT * FROM incidents")
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["category"] == "Deauthentication flood" and incident["source"] == "rule"
    assert incident["deauth_rate"] >= 10 and incident["ml_prediction"] is None
    assert incident["timestamp"] >= 1700000025
    store.update_status(incident["id"], "Investigating")
    assert Storage(tmp_path/"test.sqlite3").rows("SELECT status FROM incidents")[0]["status"] == "Investigating"
    assert "deauth_rate" in csv_export(incidents)
    output = export_report(store, tmp_path/"reports")
    assert json.loads((output/"monitoring_report.json").read_text())["incidents"][0]["id"] == incident["id"]
    store.clear_synthetic()
    assert store.rows("SELECT * FROM incidents") == []


def test_ethernet_capture_rejected(tmp_path):
    path = tmp_path/"ether.pcap"
    wrpcap(str(path), [Ether()])
    store = Storage(tmp_path/"db.sqlite")
    sid = replay_sync(path, store, Settings(), model=False)
    result = store.rows("SELECT * FROM sessions WHERE id=?", (sid,))[0]
    assert result["status"] == "error" and "Ethernet" in result["error"]


def test_worker_start_pause_resume_stop_restart(tmp_path):
    path = generate_fixture(tmp_path/"test.pcap")
    store = Storage(tmp_path/"db.sqlite")
    monitor = Monitor(store)
    sid = monitor.start(Settings(replay_speed=10), str(path), provenance="synthetic")
    monitor.pause()
    time.sleep(.15)
    frames = monitor.pipeline.frames
    time.sleep(.15)
    assert monitor.pipeline.frames == frames
    monitor.resume()
    time.sleep(.2)
    assert monitor.pipeline.frames > frames
    monitor.stop()
    assert not monitor.active and monitor.status == "stopped"
    sid2 = monitor.start(Settings(replay_speed=1000), str(path), provenance="synthetic")
    monitor.thread.join(timeout=20)
    assert not monitor.active and monitor.status == "completed" and sid2 != sid
    assert len(store.rows("SELECT * FROM sessions")) == 2


def test_browser_lease_expires(tmp_path):
    path = generate_fixture(tmp_path/"test.pcap")
    monitor = Monitor(Storage(tmp_path/"db.sqlite"))
    monitor.start(Settings(), str(path), lease=True)
    monitor.heartbeat = time.monotonic()-31
    monitor.thread.join(timeout=3)
    assert not monitor.active and monitor.status == "stopped"


def test_csv_formula_escape():
    assert "'=cmd" in csv_export([dict(value="=cmd")])
