import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from .config import Settings


def setup_logging():
    Path("logs").mkdir(exist_ok=True)
    handler = RotatingFileHandler("logs/sentinel.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    root = logging.getLogger("wids")
    if not root.handlers:
        root.addHandler(handler)
        root.setLevel(logging.INFO)


def main():
    parser = argparse.ArgumentParser(description="SentinelWiFi passive wireless analysis")
    sub = parser.add_subparsers(dest="command", required=True)
    fixture = sub.add_parser("fixture")
    fixture.add_argument("--output", default="data/demo/synthetic_deauth.pcap")
    prepare = sub.add_parser("prepare")
    prepare.add_argument("paths", nargs="+")
    prepare.add_argument("--output", default="data/processed/windows.csv")
    prepare.add_argument("--source", required=True)
    prepare.add_argument("--provenance", choices=["genuine", "synthetic"], default="genuine")
    prepare.add_argument("--recording-id", default="recording-1")
    train = sub.add_parser("train")
    train.add_argument("--data", default="data/processed/windows.csv")
    train.add_argument("--model", default="models/random_forest.joblib")
    replay = sub.add_parser("replay")
    replay.add_argument("path")
    replay.add_argument("--db", default="data/sentinel.sqlite3")
    replay.add_argument("--provenance", default="user capture")
    export = sub.add_parser("export")
    export.add_argument("--db", default="data/sentinel.sqlite3")
    export.add_argument("--output", default="reports")
    sub.add_parser("interfaces")
    args = parser.parse_args()
    setup_logging()
    if args.command == "fixture":
        from .fixture import generate_fixture
        print(generate_fixture(args.output))
    elif args.command == "prepare":
        from .dataset import prepare_csv
        print(json.dumps(prepare_csv(args.paths, args.output, source=args.source, provenance=args.provenance, recording_id=args.recording_id), indent=2))
    elif args.command == "train":
        from .training import train
        print(json.dumps(train(args.data, args.model)["metrics"], indent=2))
    elif args.command == "replay":
        from .storage import Storage
        from .replay import replay_sync
        store = Storage(args.db)
        sid = replay_sync(args.path, store, store.get_settings(), args.provenance)
        print(json.dumps(store.rows("SELECT * FROM sessions WHERE id=?", (sid,))[0], indent=2))
        print(f"Incidents: {len(store.rows('SELECT id FROM incidents WHERE session_id=?', (sid,)))}")
    elif args.command == "export":
        from .storage import Storage
        from .reporting import export_report
        print(export_report(Storage(args.db), args.output))
    elif args.command == "interfaces":
        from .capture import available_interfaces
        print(available_interfaces())


if __name__ == "__main__":
    main()
