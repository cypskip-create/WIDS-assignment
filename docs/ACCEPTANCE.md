# Delivery audit

This is a working WIDS prototype, with explicit external dependencies rather than a claim that every academic task is finished.

| Requirement | Verification / status |
|---|---|
| Documented installation | Editable package install executed; README and INSTALLATION commands supplied |
| Dashboard launches | Streamlit served on localhost and inspected in browser |
| Import Wi-Fi traffic | Raw PCAP plus reviewed labeled Wireshark CSV adapter implemented and executed |
| Raw deauthentication identification | Type 0/subtype 12 parser tests and real PCAP replay |
| Correct frame rates | Fixed-duration rates tested with explicit window boundaries |
| Genuine Random Forest | Actual sklearn fit on public publisher labels |
| Genuine supervised evaluation | WPA3 Deauth subset, 122,306 packets, 6,286 eligible windows |
| Accuracy/confusion matrix | Actual saved execution: 99.50%, matrix [[2645,12],[2,143]] |
| Train/test isolation | Purged 60-second blocks; disjoint groups; train-only imputation; duplicate-feature limitation disclosed |
| Flood detection | Synthetic replay and genuine deauth PCAP produced persisted detections |
| Automatic alerts and SQLite | Transactional observations/incidents; full pipeline test |
| Dashboard incident display | AppTest verifies persisted incident; real browser evidence saved |
| Offline replay | Start/pause/resume/stop/restart controls and deterministic fast CLI path |
| ML integrity | No invented results; feature/window/step compatibility checks; missing model uses rule only |
| Runtime lifecycle | Cached worker, no automatic start on rerun, stop events, browser lease and startup recovery |
| Automated tests | Final run: 42 passed, no failures/skips; reports/tests.xml |
| Reporting | Actual CSV/JSON, model metadata, confusion matrix and feature importance |
| A1 poster | Generator and rendered 841 × 594 mm landscape PDF; personal details remain placeholders |
| Demonstration/AI declaration | Ten-minute guide and transparent AI usage statement included |
| AWID3 evaluation | PENDING publisher approval/download; current score is not AWID |
| Optional live hardware monitoring | Linux implementation provided; NOT exercised on Windows host |
| Independent-session ML validation | PENDING more independently collected/labeled recordings |
| WIPS prevention | Optional extension Protocol only; no network enforcement implemented |
| Final video | PENDING student recording in week after submission |
| Repository push | Target: https://github.com/cypskip-create/WIDS-assignment, main; user-authorized commit identity configured |

Scores are preliminary within-recording evidence. 1,023 test feature rows repeat training values. Support counts overlapping windows, not independent events. Author ground-truth labels have not been independently audited. MAC spoofing, radio conditions and data-domain shifts remain material limitations. See MODEL.md and DATASET.md.
