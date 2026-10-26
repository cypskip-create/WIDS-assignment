"""Prepare the downloaded WPA3 Deauth recording in natural file order."""
import re
from pathlib import Path
from wids.dataset import prepare_csv

if __name__ == "__main__":
    paths = sorted(Path("data/raw/wpa3").glob("2. Deauth_*.csv"), key=lambda p: int(re.search(r"_(\d+)\.csv$", p.name)[1]))
    print(prepare_csv(paths, source="The WPA3 Dataset - hsngccu/WPA3-dataset, MIT, Deauth recording", recording_id="wpa3-deauth-20240416"))
