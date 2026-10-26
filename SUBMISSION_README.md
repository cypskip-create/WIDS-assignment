# SentinelWiFi submission package

Project: Machine Learning-Based Wireless Intrusion Detection System.

Student: **[Fill your name]**

Registration number: **[Fill your number]**

Institution: **[Fill institution]**

Lecturer: **[Fill lecturer]**

## What to submit

1. **SentinelWiFi_submission.zip**: complete source, synthetic offline PCAP, trained trusted-local model, derived labeled feature windows, actual evaluation and test evidence, screenshots, technical documentation, poster and demonstration guide.
2. **SentinelWiFi_A1.pdf**: one-page A1 landscape scientific poster. Fill personal/institutional placeholders before the final hand-in. The source generator is `scripts/generate_poster.py`.
3. **Repository**: https://github.com/cypskip-create/WIDS-assignment (main). Raw datasets and virtual environment are excluded; reproducible acquisition and training commands are included.
4. **Video**: personally record the ten-minute demonstration in the week after submission, as required by the assignment. This package does not contain a recorded video. Use `docs/DEMONSTRATION.md`.

Check the lecturer's upload rules for whether the poster and ZIP are uploaded separately. No rubric, submission portal or exact submission deadline was supplied, so those details remain yours to verify.

## Run the application after extracting

Open a terminal in the extracted `SentinelWiFi` folder:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m streamlit run app.py
```

Linux: use `.venv/bin/python`. Visit http://127.0.0.1:8501. The ZIP includes the locally trained model and derived feature table, so no raw-data download is needed to run the demonstration. Load serialized models only from trusted sources. If sklearn versions differ, install the tested versions from `requirements-lock.txt` or retrain with `python -m scripts.train_model` using the included derived feature table.

Open Wireless Traffic Monitor → Synthetic PCAP demo → Start / Restart. The valid generated packets are processed, counted, classified and persisted. The flood begins at capture second 25. The fixture is synthetic and never transmitted. It demonstrates software behavior, not real-world model accuracy. Stop and restart creates a new session; history remains visible.

## Evidence map

| Evidence | Location inside the project |
|---|---|
| Actual supervised results and provenance | reports/evaluation.json |
| Held-out actual vs predicted labels | reports/predictions.csv |
| Confusion matrix and feature importance | reports/confusion_matrix.png, reports/feature_importance.png |
| Matched CSV/PCAP predictive compatibility | reports/feature_compatibility.json |
| Automated test execution | reports/tests.xml |
| Packet-derived persisted incidents | reports/incidents.csv, reports/monitoring_report.json |
| Actual implementation screenshots | reports/screenshots/ |
| Dataset license and pinned checksums | docs/sources/ |
| Technical explanation for oral defense | docs/TECHNICAL_DEFENSE.md |
| AI assistance declaration | docs/AI_USAGE.md |
| Explicit delivery limitations | docs/ACCEPTANCE.md |

The evaluated data is the genuine publisher-labeled WPA3 Deauth subset, **not AWID3**. AWID3 access request is confirmed and awaiting approval. The split is purged temporal blocks within one recording, not independent-session validation. RSSI mean and variability are analysis-only because the CSV and Scapy select different antenna namespaces; the common classifier uses 16 verified features from 18 extracted measurements. Full details and exact metrics are in MODEL.md and evaluation.json.

## Before submission

- Fill poster and cover identity fields; do not submit invented details.
- Read the technical explanation and be able to defend the source, features, split and limitations.
- Rerun tests and the replay on the machine used for the demonstration.
- Keep the AI declaration and dataset citation/license with the source.
- Do not describe synthetic replay as captured attack traffic, the current score as AWID3 evaluation, or the optional Linux capture as hardware-tested on Windows.
- Record and submit the video in the required week after submission.

`SUBMISSION_SHA256.json` inside the archive fingerprints every packaged source/evidence file. The sibling `.zip.sha256` file verifies the ZIP. The local SQLite database, raw packet downloads, virtual environment, caches, Git credentials and Git history are not bundled.
