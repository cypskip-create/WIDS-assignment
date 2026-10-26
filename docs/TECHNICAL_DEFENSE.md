# Oral explanation and code walkthrough

**What is machine learning?** A classifier learns patterns from examples with known answers. Here the answers are the dataset publisher's normal/attack labels. Training adjusts a Random Forest using only the training partition; the held-out partition estimates how well it predicts observations it was not fitted on.

**Why Random Forest?** A tree asks questions such as whether a traffic rate or proportion is above a learned threshold. A forest combines many trees, making the decision less sensitive to any one tree. It is suitable for small numeric traffic feature tables and easy to inspect, though high accuracy in one recording does not establish deployment quality.

**What is a feature?** A measurable summary, such as frames per second or proportion of deauthentication frames. Five seconds of packets from each transmitter/BSSID become 18 numbers; the classifier uses 16. RSSI mean and variability remain analysis-only because publisher CSVs and Scapy choose different antenna namespaces. The 16 common inputs were checked against a matched real PCAP/CSV pair. A frame arriving exactly at a scheduled snapshot is added after that snapshot. Missing RSSI is missing, never invented. Transmitter addresses are context, not classifier inputs.

**What is a deauthentication?** An IEEE 802.11 management message ending authentication. It has type 0 and subtype 12. A legitimate access point may send one during ordinary operation, so the presence of one frame does not prove an attack. Many such frames concentrated in time can indicate a flood. Protected Management Frames and hardware/driver behavior affect what the monitor can observe.

**How does detection work?** The rate rule counts observed deauthentications over five seconds. At the default 10/s threshold, at least 50 in that interval are needed. Independently the compatible forest predicts normal or malicious from exactly the training features. Either can produce an incident; the database records which fired. If the rule fires and ML says normal, both facts remain visible.

**How does an incident reach the browser?** The background worker parses packets, aggregates windows, evaluates decisions, checks cooldown and commits evidence to SQLite. Streamlit refresh reads the database. Widgets do not create alerts themselves. You can close the dashboard and inspect the persisted incidents with the CLI export. The browser heartbeat stops long-running capture after tabs close.

**Why split by time blocks?** Adjacent rolling windows can share almost every packet. Randomly assigning those windows to train and test would leak nearly identical observations. This implementation keeps whole purged blocks apart. However, all current data comes from one recording and many feature values repeat, so this is weaker than testing a different attack run or network.

**How should I explain the matrix?** Rows are actual labels, columns are predicted. Top-left are normal windows correctly kept normal. Top-right are false alarms. Bottom-left are missed malicious windows. Bottom-right are detected malicious windows. Precision asks how many predicted malicious windows really had malicious labels; recall asks how many labeled malicious windows were found. False positives cost investigation time; false negatives hide threats.

**What does the system not prove?** It does not verify an attacker's identity, block a device, decrypt payloads, detect every attack type, or prove reliability on other networks. It is passive WIDS. A countermeasure interface is only a future extension, not network enforcement. Ordinary Windows Wi-Fi traffic usually lacks raw management frames; replay is the reliable laboratory demonstration.

Suggested code route: `packet_parser.py` → `window_aggregator.py` → `feature_extractor.py` → `detection.py` → `alerts.py` → `storage.py` → `dashboard/views.py`. Then inspect `dataset.py`, `training.py`, `inference.py` and the full integration test. Be prepared to explain each feature, the threshold, data provenance and evaluation limitations without reading a script.
