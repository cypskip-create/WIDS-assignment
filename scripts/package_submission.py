"""Build a portable hand-in archive; optionally copy to a requested school folder."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import zipfile


def files_to_include(root):
    files = []
    for name in ("wids", "dashboard", "scripts", "tests", "docs", ".streamlit", ".github", "reports", "data/demo", "output/pdf"):
        folder = root/name
        files.extend(p for p in folder.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix not in (".pyc", ".pyo"))
    files.extend(root/name for name in ("app.py", "pyproject.toml", "requirements.txt", "requirements-lock.txt", "README.md", "SUBMISSION_README.md", ".env.example", ".gitignore", ".gitattributes"))
    for name in ("models/random_forest.joblib", "models/random_forest.joblib.json", "data/processed/windows.csv", "data/processed/windows.csv.json"):
        path = root/name
        if path.exists():
            files.append(path)
    return sorted(set(files))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = root/"output/submission"
    output.mkdir(parents=True, exist_ok=True)
    files = files_to_include(root)
    missing = [p for p in files if not p.exists()]
    if missing:
        raise ValueError(f"Submission files missing: {missing}")
    manifest = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    archive = output/"SentinelWiFi_submission.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in files:
            bundle.write(path, "SentinelWiFi/"+path.relative_to(root).as_posix())
        bundle.writestr("SentinelWiFi/SUBMISSION_SHA256.json", json.dumps(manifest, indent=2))
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None:
            raise RuntimeError("Submission ZIP integrity check failed")
        if any("/.venv/" in name or "/data/raw/" in name or "/.git/" in name for name in bundle.namelist()):
            raise RuntimeError("Unexpected private/runtime data in archive")
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output/"SentinelWiFi_submission.zip.sha256").write_text(checksum+"  "+archive.name+"\n", encoding="utf-8")
    if args.destination:
        destination = args.destination.resolve()
        destination.mkdir(parents=True, exist_ok=True)
        project = destination/"SentinelWiFi"
        # No deletions: preserve unrelated existing school files.
        for path in files:
            target = project/path.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        (project/"SUBMISSION_SHA256.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        shutil.copy2(archive, destination/archive.name)
        shutil.copy2(output/"SentinelWiFi_submission.zip.sha256", destination/"SentinelWiFi_submission.zip.sha256")
        shutil.copy2(root/"output/pdf/sentinelwifi_A1.pdf", destination/"SentinelWiFi_A1.pdf")
        shutil.copy2(root/"SUBMISSION_README.md", destination/"SUBMISSION_README.md")
        if hashlib.sha256((destination/archive.name).read_bytes()).hexdigest() != checksum:
            raise RuntimeError("Copied archive checksum mismatch")
        print(f"Project: {project}\nZIP: {destination/archive.name}\nSHA256: {checksum}")
    else:
        print(f"ZIP: {archive}\nSHA256: {checksum}")


if __name__ == "__main__":
    main()
