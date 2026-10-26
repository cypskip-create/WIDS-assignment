# A1 scientific poster content

Format: A1 landscape, 841 × 594 mm. Generator: `python -m scripts.generate_poster`. Output: `output/pdf/sentinelwifi_A1.pdf`.

Title: Machine Learning-Based Wireless Intrusion Detection System.
Subtitle: Detection of Deauthentication Flood Attacks Using Random Forest.
Project: SentinelWiFi.

Student name, registration number, institution and lecturer are intentionally placeholders. They must be filled before submission.

Introduction/problem: Wireless management messages can be abused to disrupt connectivity. Passive WIDS monitors visible frame metadata, identifies abnormal concentration and preserves explainable evidence.

Objectives: parse raw 802.11 frames, aggregate meaningful windows, classify with a genuine Random Forest, detect deauthentication floods, persist alerts and report measured held-out performance.

Methodology: genuine publisher-labeled WPA3 Deauth subset; chunked CSV adaptation; common 18-feature window schema; purged 60-second blocks; fixed grouped holdout; train-only median imputation; Random Forest; transparent complementary rate rule; SQLite and dashboard.

Architecture: Traffic/PCAP → Metadata → Rolling Features → Rule + ML → SQLite Alerts → Dashboard. Labeled CSV → same features → grouped train/evaluate → saved model, shown as a separate path.

Results must come directly from `reports/evaluation.json`; confusion matrix and feature importance are generated from the actual fitted model. Screenshot evidence must be taken from the working application. Synthetic replay must be described separately from genuine model evaluation.

Conclusion: the prototype performs packet-to-alert processing and evidence inspection without monitor-mode hardware, while permitting optional authorized Linux capture. Limitations: single recording, repeated features, radio conditions, MAC spoofing and lack of independent-session validation. Future work: approved AWID import, multiple independent captures, site-specific false-positive tuning and explicit authenticated AP countermeasures.

References: publisher WPA3 repository/license; Chatzoglou et al. AWID3, DOI 10.1109/ACCESS.2021.3061609; Scapy; Scikit-learn. A draft banner appears if evaluation or implementation screenshot is missing. The poster does not claim an unperformed live capture or recorded video.
