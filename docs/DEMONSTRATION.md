# Ten-minute demonstration

Prepare before presenting:

```text
python -m wids.cli fixture
python -m pytest -q
python -m streamlit run app.py
```

To reproduce genuine model results first:

```text
python scripts/download_public_dataset.py
python -m scripts.prepare_dataset
python -m scripts.train_model
```

Do not spend the presentation downloading or training. Check that the model window/step match Settings. Set playback to 1x, threshold 10 fps, window 5 seconds and cooldown 30 seconds. If repeating the synthetic example, explicitly clear completed synthetic history in Settings before the demonstration, or identify the new session ID. Do not clear real evidence.

| Minute | Demonstration |
|---|---|
| 0–1 | Explain the problem: legitimate disconnect messages can be abused in floods. This is passive defensive monitoring. |
| 1–2 | Show the architecture, genuine WPA3 dataset citation, AWID access status and separation of train/test blocks. Explain that the demo PCAP is synthetic. |
| 2–4 | Open Machine Learning Analytics. Explain 18 extracted measurements and 16 verified classifier inputs, Random Forest, training/test counts, actual metrics and matrix. Mention the RSSI exclusion, single-recording and duplicate-feature limitations. |
| 4–6 | Open Wireless Traffic Monitor, choose Synthetic PCAP demo and Start. Normal period is 0–15 capture seconds; occasional deauths 15–25. Show counters and metadata. Demonstrate pause/resume briefly. The fixture is only 50 seconds, so use the remaining minute to explain fields or restart once. |
| 6–8 | Restart replay if needed. Flood begins at capture second 25 and lasts 10 seconds. A rule alert normally appears around second 26 because 100 observed frames / 5 seconds exceeds 10/s. Model support may differ; show the actual source. Open Attack Detection and select the just-created session. Explain count, window, threshold, BSSID and cooldown. |
| 8–9 | Open Security Incidents, filter the new session's observed MAC, inspect the explanation and features, save Investigating, export CSV. |
| 9–10 | Explain spoofed MACs, radio hardware limits, future independent-session evaluation, AWID comparison and optional authorized AP integration. No packet injection or blocking is claimed. |

Fallback without browser/live hardware:

```text
python -m wids.cli replay data/demo/synthetic_deauth.pcap --provenance synthetic
python -m wids.cli export
python -m scripts.evaluate_model
```

Inspect `reports/incidents.csv`, `reports/observations.csv`, `reports/monitoring_report.json`, `reports/confusion_matrix.png` and the actual dashboard screenshots. Without a trained model the rule still detects the flood, but do not claim ML prediction occurred. Without genuine data, mark ML evaluation pending and use a draft poster.

The assignment requires the video to be recorded **in the week after submission**. No submission date was supplied, so no calendar date is invented. The video has not been recorded by this build. The student must understand, record and defend the work, including disclosing AI assistance.
