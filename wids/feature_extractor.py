from collections import Counter
import numpy as np

SCHEMA_VERSION = "80211-window-v2"
FEATURES = ["total_frames", "frames_per_second", "management_per_second", "deauth_count", "deauth_per_second", "disassoc_count", "beacon_count", "auth_count", "probe_request_count", "deauth_ratio", "distinct_destinations", "retry_ratio", "mean_frame_size", "mean_rssi", "std_rssi", "rssi_coverage", "broadcast_ratio", "reason7_ratio"]
# Publisher CSV and Scapy select different antenna namespaces in the inspected
# multi-antenna Radiotap capture. Preserve real RSSI for analysis but never feed
# incomparable signal statistics into the shared packet classifier.
MODEL_FEATURES = [name for name in FEATURES if name not in ("mean_rssi", "std_rssi")]


def extract_features(frames, window_seconds):
    if not frames or window_seconds <= 0:
        raise ValueError("A nonempty observation and positive window are required")
    n = len(frames)
    management = Counter(f.subtype for f in frames if f.type == 0)
    signals = [f.rssi for f in frames if f.rssi is not None]
    deauth = management[12]
    values = [n, n/window_seconds, sum(management.values())/window_seconds,
              deauth, deauth/window_seconds, management[10], management[8], management[11], management[4],
              deauth/n, len({f.destination for f in frames if f.destination}),
              sum(f.retry for f in frames)/n, sum(f.length for f in frames)/n,
              float(np.mean(signals)) if signals else np.nan,
              float(np.std(signals)) if signals else np.nan, len(signals)/n,
              sum(f.multicast for f in frames)/n,
              sum(f.type == 0 and f.subtype == 12 and f.reason == 7 for f in frames)/deauth if deauth else 0]
    return dict(zip(FEATURES, values, strict=True))
