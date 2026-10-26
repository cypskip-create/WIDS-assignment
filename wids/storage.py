from contextlib import contextmanager
from dataclasses import asdict
import csv
import io
import json
from pathlib import Path
import sqlite3
import time
import uuid


class Storage:
    def __init__(self, path="data/sentinel.sqlite3"):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, started REAL, ended REAL,
                    source TEXT, provenance TEXT, status TEXT, frames INTEGER DEFAULT 0,
                    skipped INTEGER DEFAULT 0, error TEXT, settings TEXT);
                CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY, session_id TEXT,
                    timestamp REAL, transmitter TEXT, bssid TEXT, destination TEXT, features TEXT,
                    rule_fired INTEGER, ml_prediction INTEGER, confidence REAL, source TEXT);
                CREATE INDEX IF NOT EXISTS obs_session ON observations(session_id, timestamp);
                CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, session_id TEXT, timestamp REAL,
                    category TEXT, severity TEXT, source TEXT, transmitter TEXT, destination TEXT,
                    bssid TEXT, frame_count INTEGER, deauth_rate REAL, ml_prediction INTEGER,
                    confidence REAL, explanation TEXT, status TEXT DEFAULT 'New', evidence TEXT);
                CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, session_id TEXT,
                    timestamp REAL, kind TEXT, details TEXT);
                CREATE TABLE IF NOT EXISTS models(id INTEGER PRIMARY KEY, timestamp REAL, path TEXT, metadata TEXT);
                CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
                PRAGMA user_version=1;
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def rows(self, query, params=()):
        with self.connect() as db:
            return [dict(row) for row in db.execute(query, params)]

    def execute(self, query, params=()):
        with self.connect() as db:
            db.execute(query, params)

    def create_session(self, source, provenance, settings):
        sid = str(uuid.uuid4())
        self.execute("INSERT INTO sessions(id,started,source,provenance,status,settings) VALUES(?,?,?,?,?,?)",
                     (sid, time.time(), source, provenance, "running", json.dumps(settings.to_dict())))
        self.event(sid, "start", source)
        return sid

    def event(self, sid, kind, details):
        self.execute("INSERT INTO events(session_id,timestamp,kind,details) VALUES(?,?,?,?)", (sid, time.time(), kind, details))

    def progress(self, sid, frames, skipped):
        self.execute("UPDATE sessions SET frames=?,skipped=? WHERE id=?", (frames, skipped, sid))

    def finish(self, sid, status, error=None):
        self.execute("UPDATE sessions SET ended=?,status=?,error=? WHERE id=?", (time.time(), status, error, sid))
        self.event(sid, status, error or status)

    def record(self, sid, observation, decision, incident=None):
        """Observation, decision event and optional incident commit atomically."""
        with self.connect() as db:
            db.execute("INSERT INTO observations(session_id,timestamp,transmitter,bssid,destination,features,rule_fired,ml_prediction,confidence,source) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (sid, observation.timestamp, observation.transmitter, observation.bssid, observation.destination,
                        json.dumps(observation.features, allow_nan=True), decision.rule_fired, decision.ml_prediction, decision.confidence, decision.source))
            if incident:
                keys = list(incident)
                db.execute(f"INSERT INTO incidents({','.join(keys)}) VALUES({','.join('?' for _ in keys)})", tuple(incident.values()))
                db.execute("INSERT INTO events(session_id,timestamp,kind,details) VALUES(?,?,?,?)",
                           (sid, time.time(), "alert", incident["explanation"]))

    def update_status(self, incident_id, status):
        if status not in ("New", "Investigating", "Resolved"):
            raise ValueError("Unsupported incident status")
        with self.connect() as db:
            row = db.execute("SELECT session_id FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if row is None:
                raise ValueError("Incident does not exist")
            db.execute("UPDATE incidents SET status=? WHERE id=?", (status, incident_id))
            db.execute("INSERT INTO events(session_id,timestamp,kind,details) VALUES(?,?,?,?)",
                       (row[0], time.time(), "status", f"{incident_id}: {status}"))

    def get_settings(self):
        from .config import Settings
        rows = self.rows("SELECT value FROM settings WHERE key='preferences'")
        return Settings(**json.loads(rows[0]["value"])) if rows else Settings()

    def save_settings(self, settings):
        self.execute("INSERT OR REPLACE INTO settings VALUES('preferences',?)", (json.dumps(settings.to_dict()),))
        self.event(None, "configuration", json.dumps(settings.to_dict()))

    def prune(self, days):
        cutoff = time.time()-days*86400
        with self.connect() as db:
            for table in ("observations", "incidents", "events"):
                db.execute(f"DELETE FROM {table} WHERE session_id IN (SELECT id FROM sessions WHERE ended < ?)", (cutoff,))
            db.execute("DELETE FROM sessions WHERE ended < ?", (cutoff,))

    def clear_synthetic(self):
        with self.connect() as db:
            for table in ("observations", "incidents", "events"):
                db.execute(f"DELETE FROM {table} WHERE session_id IN (SELECT id FROM sessions WHERE provenance='synthetic' AND status NOT IN ('running','paused'))")
            db.execute("DELETE FROM sessions WHERE provenance='synthetic' AND status NOT IN ('running','paused')")


def csv_export(rows):
    out = io.StringIO(newline="")
    if rows:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        for row in rows:
            # Prevent spreadsheet formula injection in untrusted capture metadata.
            writer.writerow({k: "'"+v if isinstance(v, str) and v.startswith(("=", "+", "-", "@")) else v for k, v in row.items()})
    return out.getvalue()
