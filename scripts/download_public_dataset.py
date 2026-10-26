"""Download an explicitly licensed research subset, pinned to a commit.

No attack scripts are downloaded or executed. Raw data stays gitignored.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen, Request

REPO = "hsngccu/WPA3-dataset"
REVISION = "e07113327e2012a861f3e273e10ed9b02f0491f4"


def fetch(url):
    with urlopen(Request(url, headers={"User-Agent": "SentinelWiFi-research"}), timeout=90) as response:
        return response.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="data/raw/wpa3")
    args = parser.parse_args()
    target = Path(args.output)
    target.mkdir(parents=True, exist_ok=True)
    tree = json.loads(fetch(f"https://api.github.com/repos/{REPO}/git/trees/{REVISION}?recursive=1"))
    commit = tree["sha"]
    entries = [x for x in tree["tree"] if x["path"].startswith("The_WPA3_Dataset_csv/2. Deauth/") and x["path"].endswith(".csv")]
    # Include a real PCAP to verify packet replay against the fitted schema.
    entries += [x for x in tree["tree"] if x["path"].startswith("The_WPA3_Dataset/2. Deauth/2. Deauth_00056_")]
    entries += [x for x in tree["tree"] if x["path"] in ("LICENSE", "README.md")]

    def download(entry):
        url = f"https://raw.githubusercontent.com/{REPO}/{commit}/"+quote(entry["path"])
        path = target/Path(entry["path"]).name
        if not path.exists() or path.stat().st_size != entry["size"]:
            payload = fetch(url)
            path.write_bytes(payload)
        payload = path.read_bytes()
        # Verify existing cached data too, not just newly downloaded files.
        blob = hashlib.sha1(f"blob {len(payload)}\0".encode()+payload).hexdigest()
        if blob != entry["sha"]:
            raise ValueError(f"Integrity check failed: {path.name}")
        return dict(file=path.name, source=url, bytes=path.stat().st_size,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(), git_blob=entry["sha"])

    with ThreadPoolExecutor(max_workers=4) as pool:
        files = list(pool.map(download, entries))
    manifest = dict(dataset="The WPA3 Dataset - Deauth subset", repository=f"https://github.com/{REPO}",
                    commit=commit, license="MIT (upstream LICENSE retained)", files=files,
                    provenance="genuine research capture; original publisher packet labels; single attack recording split into files")
    (target/"manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Verified {len(files)} files at commit {commit}")


if __name__ == "__main__":
    main()
