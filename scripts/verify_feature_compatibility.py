"""Compare matched genuine CSV and PCAP features without fitting a classifier."""
from pathlib import Path
import json
import numpy as np
from scapy.utils import PcapReader
from wids.config import Settings
from wids.dataset import iter_csv_frames
from wids.packet_parser import parse_packet
from wids.window_aggregator import WindowAggregator
from wids.feature_extractor import FEATURES, MODEL_FEATURES


def main():
    root = Path("data/raw/wpa3")
    capture = next(root.glob("*00056*.pcap"))
    csv_path = root/"2. Deauth_57.csv"
    packet_agg, csv_agg = WindowAggregator(Settings()), WindowAggregator(Settings())
    packet_observations, csv_observations = [], []
    with PcapReader(str(capture)) as reader:
        for packet in reader:
            frame = parse_packet(packet)
            if frame:
                packet_observations.extend(packet_agg.push(frame))
    packet_observations.extend(packet_agg.flush())
    for frame in iter_csv_frames([csv_path]):
        csv_observations.extend(csv_agg.push(frame))
    csv_observations.extend(csv_agg.flush())
    if len(packet_observations) != len(csv_observations):
        raise ValueError("Matched recording produced different numbers of observations")
    for first, second in zip(packet_observations, csv_observations, strict=True):
        if (first.transmitter, first.bssid) != (second.transmitter, second.bssid):
            raise ValueError("Observation context differs")
    differences = {name: sum(not np.isclose(a.features[name], b.features[name], equal_nan=True)
                            for a, b in zip(packet_observations, csv_observations, strict=True)) for name in FEATURES}
    result = dict(pcap=capture.name, csv=csv_path.name, observations=len(packet_observations),
                  differences=differences, predictive_features=MODEL_FEATURES,
                  compatible=all(differences[name] == 0 for name in MODEL_FEATURES),
                  note="RSSI mean/std remain analysis-only due to publisher/Scapy antenna namespace selection. Float timestamp rounding does not alter the inspected windows.")
    Path("reports/feature_compatibility.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    if not result["compatible"]:
        raise ValueError(f"Predictive feature mismatch: {differences}")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
