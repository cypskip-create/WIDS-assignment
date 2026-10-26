"""Explicit packet-CSV adapter. Arbitrary CSV columns never enter packet ML."""
from dataclasses import replace
import hashlib
import json
import logging
import math
from pathlib import Path
import numpy as np
import pandas as pd
from .config import Settings
from .feature_extractor import FEATURES, SCHEMA_VERSION
from .packet_parser import Frame, is_multicast
from .window_aggregator import WindowAggregator

NORMAL = {"normal", "benign", "0"}
ATTACKS = {"1", "malicious", "attack", "deauth", "deauthentication", "disassoc", "disassociation", "flooding", "injection", "impersonation", "krack", "kr00k", "rogue_ap", "evil_twin", "beacon", "(re)assoc", "ssh", "botnet", "malware", "sql_injection", "ssdp", "website_spoofing"}
REQUIRED = ["frame.time_epoch", "frame.len", "wlan.fc.type", "wlan.fc.subtype", "Label"]
OPTIONAL = ["wlan.ta", "wlan.ra", "wlan.bssid", "wlan.fc.retry", "radiotap.dbm_antsignal", "radiotap.channel.freq", "wlan.fixed.reason_code"]


def map_label(value):
    label = str(value).strip().lower()
    if label in NORMAL:
        return 0
    if label in ATTACKS:
        return 1
    raise ValueError(f"Unknown label {value!r}; supply a reviewed label map rather than guessing")


def number(value, default=None):
    try:
        result = float(value)
        return result if math.isfinite(result) else default
    except (ValueError, TypeError):
        return default


def text(value):
    return str(value).lower() if pd.notna(value) and str(value).strip() else None


def inspect_csv(path):
    header = list(pd.read_csv(path, nrows=0).columns)
    return {"columns": header, "missing_required": sorted(set(REQUIRED)-set(header)), "sample": pd.read_csv(path, nrows=8).fillna("").to_dict("records")}


def iter_csv_frames(paths, chunk_size=20000):
    for path in paths:
        columns = list(pd.read_csv(path, nrows=0).columns)
        missing = set(REQUIRED)-set(columns)
        if missing:
            raise ValueError(f"{path}: missing packet CSV columns {sorted(missing)}. AWID versions require explicit schema inspection.")
        for chunk in pd.read_csv(path, usecols=[c for c in REQUIRED+OPTIONAL if c in columns], chunksize=chunk_size, low_memory=False):
            for row in chunk.to_dict("records"):
                label = str(row["Label"]).strip()
                map_label(label)
                ts = number(row["frame.time_epoch"])
                typ, sub = number(row["wlan.fc.type"]), number(row["wlan.fc.subtype"])
                length = number(row["frame.len"])
                if ts is None or typ not in (0, 1, 2, 3) or sub is None or length is None:
                    continue
                typ, sub = int(typ), int(sub)
                bssid = text(row.get("wlan.bssid")) if typ in (0, 2) else None
                dst = text(row.get("wlan.ra"))
                yield Frame(ts, typ, sub, text(row.get("wlan.ta")), dst, bssid, int(length),
                            number(row.get("radiotap.dbm_antsignal")), number(row.get("radiotap.channel.freq")),
                            number(row.get("wlan.fixed.reason_code")), bool(number(row.get("wlan.fc.retry"), 0)),
                            is_multicast(dst), label)


def prepare_csv(paths, output="data/processed/windows.csv", settings=None, source="User-provided labeled capture", provenance="genuine", recording_id="recording-1"):
    """Paths must be in capture order and belong to ONE recording.

    Labels come from publisher/user ground truth, never inferred from rule rates.
    Non-overlapping 60-second temporal blocks are purged by one full observation
    window at their beginning before deterministic block-level holdout.
    """
    settings = settings or Settings()
    aggregator = WindowAggregator(settings)
    rows, first, packet_count, labels = [], None, 0, {}

    def accept(observation):
        block = int((observation.timestamp-first)//60)
        block_start = first + block*60
        # Snapshot must contain no packet from preceding temporal block.
        if observation.timestamp-block_start < settings.window_seconds:
            return
        if not observation.labels:
            return
        mapped = [map_label(x) for x in observation.labels]
        rows.append(dict(observation.features, label=int(any(mapped)),
                         original_labels="|".join(sorted(set(observation.labels))),
                         malicious_fraction=sum(mapped)/len(mapped),
                         timestamp=observation.timestamp, group=f"{recording_id}:block-{block}",
                         recording_id=recording_id))

    for frame in iter_csv_frames(paths):
        if first is None:
            first = frame.timestamp
        packet_count += 1
        labels[frame.label] = labels.get(frame.label, 0)+1
        for observation in aggregator.push(frame):
            accept(observation)
    for observation in aggregator.flush():
        accept(observation)
    if not rows:
        raise ValueError("No usable labeled windows; check schema, capture duration and label coverage")
    frame = pd.DataFrame(rows)
    # Inspect duplicates across the actual predictive representation.
    duplicate_features = int(frame.duplicated(subset=FEATURES).sum())
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output, index=False)
    metadata = dict(schema_version=SCHEMA_VERSION, features=FEATURES, window_seconds=settings.window_seconds,
                    step_seconds=settings.step_seconds, source=source, provenance=provenance,
                    packet_count=packet_count, packet_labels=labels, windows=len(frame),
                    class_distribution={str(k): int(v) for k, v in frame.label.value_counts().items()},
                    duplicate_feature_rows=duplicate_features,
                    split_design="60-second blocks; first full observation window purged per block; block-disjoint holdout",
                    limitations="Temporal holdout within one recording is weaker than independent-session evaluation; window label is any publisher-labeled attack frame; background traffic in attack windows is mixed.",
                    files=[dict(name=Path(p).name, sha256=hashlib.sha256(Path(p).read_bytes()).hexdigest()) for p in paths])
    Path(str(output)+".json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    logging.getLogger(__name__).info("prepared packets=%s windows=%s", packet_count, len(frame))
    return metadata
