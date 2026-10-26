# Executed testing

The final full regression run on 26 October 2026 completed **42 passed, 0 failed, 0 skipped** in 64.22 seconds. Machine-readable evidence: `reports/tests.xml`. Python 3.12.14 on Windows; exact package versions are in `requirements-lock.txt` and model metadata. The suite was executed after fixing accumulated replay wait overhead with absolute-time pacing. Earlier failing runs are not counted as passes.

Command:

```text
python -m pytest -q --junitxml=reports/tests.xml
```

In this desktop sandbox, the restricted Windows temp directory and blocked local socket initialization prevented the default AppTest environment from starting. The successful run used a workspace-local temp folder and approved local execution:

```powershell
$env:TEMP = (Resolve-Path tmp).Path
$env:TMP = $env:TEMP
.venv\Scripts\python.exe -m pytest -q --basetemp=tmp/tests/final --junitxml=reports/tests.xml
```

Use a new `--basetemp` for another run, or let pytest choose the ordinary OS temp location outside the sandbox. Do not delete unrelated temporary files.

Coverage includes deauthentication and management subtype parsing, data DS/BSSID mapping, malformed/non-wireless packets, absent RSSI and MACs, frame/rate calculations, canonical order, lower window boundary and expired-state cleanup, explicit memory limits, settings validation, normal/isolated/flood decisions, cooldown, ML/rule disagreement, label validation, feature allowlisting, disjoint groups, train-only imputation, model serialization/schema/window validation, metrics/matrix consistency, CSV adaptation/purge, SQLite status/persistence, report export, Ethernet rejection, full synthetic packet-to-incident path, worker pause/resume/stop/restart, browser lease, all six dashboard pages and display of an actual persisted incident.

The unit model fixture is explicitly synthetic and stays in temporary test directories. Its scores are never published as dataset evaluation. The real training run is separate and recorded in `reports/evaluation.json`.

Additional executed checks: editable package installation; module compilation; Streamlit server startup on localhost; browser inspection of Overview, Monitor and ML Analytics; a dashboard-initiated synthetic replay reached COMPLETED with 1,320 frames and a persisted both-source alert; CLI real PCAP processing reached COMPLETED with 2,000 frames and six incidents. The genuine PCAP belongs to the source recording used in development and is functional verification, not new holdout accuracy evidence. Actual screenshots reside in `reports/screenshots/`.

Unverified: actual Linux adapter capture, radio packet-drop behavior, independent-session generalization, high-throughput stability, final AWID compatibility and a fresh dependency installation on every supported platform. The PDF poster is generated from saved results and rendered for visual review. Student identity fields and video recording remain user work.

Final schema v2 verification: all 16 predictive features match across 302 genuine PCAP/CSV observations. RSSI mean and variability remain analysis-only. The full 42-test suite was rerun after this change.
