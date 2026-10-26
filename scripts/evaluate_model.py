"""Inspect saved evaluation. Never refit on the held-out test data."""
import json
from pathlib import Path

if __name__ == "__main__":
    print(json.dumps(json.loads(Path("reports/evaluation.json").read_text())["metrics"], indent=2))
