import atexit
from collections import deque
from dataclasses import asdict
import logging
from pathlib import Path
import threading
import time
from scapy.utils import PcapReader
from .alerts import AlertManager
from .detection import Detector
from .inference import Model
from .packet_parser import parse_packet
from .window_aggregator import WindowAggregator

log = logging.getLogger(__name__)


class Pipeline:
    """Single owner per session; UI never performs detection or persistence."""
    def __init__(self, storage, settings, source, provenance="user capture", model=True):
        self.storage, self.settings = storage, settings
        self.session_id = storage.create_session(source, provenance, settings)
        self.aggregator, self.alerts = WindowAggregator(settings), AlertManager(settings)
        fitted = None
        self.model_status = "No compatible trained model; rule only"
        if model and Path(settings.model_path).exists():
            try:
                fitted = Model(settings.model_path, settings.window_seconds, settings.step_seconds)
                self.model_status = "Random Forest ready" if fitted.metadata.get("provenance") == "genuine" else "Random Forest ready (SYNTHETIC training; software test only)"
            except Exception as error:
                self.model_status = f"ML disabled: {error}"
                storage.event(self.session_id, "model_incompatible", str(error))
        self.detector = Detector(settings, fitted)
        self.frames = self.skipped = 0
        self.recent = deque(maxlen=100)
        self.last_progress = 0.0

    def observations(self, observations):
        for observation in observations:
            decision = self.detector.evaluate(observation)
            incident = self.alerts.create(self.session_id, observation, decision)
            self.storage.record(self.session_id, observation, decision, incident)

    def ingest(self, packet):
        frame = parse_packet(packet)
        if frame is None:
            self.skipped += 1
        else:
            self.frames += 1
            self.recent.append(dict(timestamp=frame.timestamp, kind=frame.name, transmitter=frame.transmitter,
                                    destination=frame.destination, bssid=frame.bssid, rssi=frame.rssi,
                                    frequency=frame.frequency, reason=frame.reason, length=frame.length))
            self.observations(self.aggregator.push(frame))
        if time.monotonic()-self.last_progress >= 0.5:
            self.storage.progress(self.session_id, self.frames, self.skipped)
            self.last_progress = time.monotonic()

    def finish(self, status="completed", error=None):
        if status != "error":
            self.observations(self.aggregator.flush())
        if self.frames == 0 and status == "completed":
            status, error = "error", "No raw IEEE 802.11 frames found. Ethernet captures cannot expose wireless deauthentication management frames."
        self.storage.progress(self.session_id, self.frames, self.skipped)
        self.storage.finish(self.session_id, status, error)


class Monitor:
    def __init__(self, storage):
        self.storage = storage
        self.thread = None
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.lock = threading.Lock()
        self.pipeline = None
        self.status = "idle"
        self.error = None
        self.heartbeat = time.monotonic()
        self.lease = False
        self.paused_total = 0.0
        atexit.register(self.stop)

    @property
    def active(self):
        return self.thread is not None and self.thread.is_alive()

    def touch(self):
        self.heartbeat = time.monotonic()

    def _cancelled(self):
        if self.lease and time.monotonic()-self.heartbeat > 30:
            self.stop_event.set()
        return self.stop_event.is_set()

    def _wait(self, duration):
        """Responsive pause/stop and time scaling, preserving remaining packet delay."""
        remaining = duration
        while remaining > 0 or self.pause_event.is_set():
            if self._cancelled():
                return False
            before = time.monotonic()
            was_paused = self.pause_event.is_set()
            self.stop_event.wait(min(remaining, 0.05) if not self.pause_event.is_set() else 0.05)
            if was_paused:
                self.paused_total += time.monotonic()-before
            else:
                remaining -= time.monotonic()-before
        return not self._cancelled()

    def start(self, settings, source, mode="replay", provenance="user capture", lease=False):
        with self.lock:
            if self.active:
                raise RuntimeError("Monitoring already active; stop the current session first")
            if mode == "replay" and not Path(source).is_file():
                raise ValueError("Capture file does not exist")
            if mode == "live":
                from .capture import validate_interface
                validate_interface(source)
            self.stop_event.clear()
            self.pause_event.clear()
            self.paused_total = 0.0
            self.touch()
            self.lease, self.status, self.error = lease, "running", None
            self.pipeline = Pipeline(self.storage, settings, source, provenance)
            self.thread = threading.Thread(target=self._run, args=(source, mode, settings), daemon=True, name="sentinel-monitor")
            self.thread.start()
            return self.pipeline.session_id

    def _run(self, source, mode, settings):
        try:
            if mode == "replay":
                first_timestamp = None
                started = time.monotonic()
                with PcapReader(str(source)) as reader:
                    for packet in reader:
                        timestamp = float(packet.time)
                        if first_timestamp is None:
                            first_timestamp = timestamp
                        # Absolute pacing catches up after parsing and OS scheduler
                        # overhead instead of accumulating a minimum wait per packet.
                        target = started + (timestamp-first_timestamp)/settings.replay_speed + self.paused_total
                        delay = max(0, target-time.monotonic())
                        if not self._wait(delay):
                            break
                        self.pipeline.ingest(packet)
            else:
                from scapy.sendrecv import sniff
                while not self._cancelled():
                    sniff(iface=source, prn=self.pipeline.ingest, store=False, timeout=1)
            self.status = "stopped" if self._cancelled() else "completed"
            self.pipeline.finish(self.status)
            row = self.storage.rows("SELECT status,error FROM sessions WHERE id=?", (self.pipeline.session_id,))[0]
            self.status, self.error = row["status"], row["error"]
        except Exception as error:
            log.exception("monitoring failed")
            self.status, self.error = "error", str(error)
            self.pipeline.finish("error", self.error)

    def pause(self):
        if self.active:
            self.pause_event.set()
            self.status = "paused"
            self.storage.execute("UPDATE sessions SET status='paused' WHERE id=?", (self.pipeline.session_id,))

    def resume(self):
        self.pause_event.clear()
        if self.active:
            self.status = "running"
            self.storage.execute("UPDATE sessions SET status='running' WHERE id=?", (self.pipeline.session_id,))

    def stop(self):
        self.stop_event.set()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=3)

    def snapshot(self):
        return dict(status=self.status, error=self.error, active=self.active,
                    session_id=self.pipeline.session_id if self.pipeline else None,
                    model_status=self.pipeline.model_status if self.pipeline else "No active pipeline",
                    recent=list(self.pipeline.recent) if self.pipeline else [])
