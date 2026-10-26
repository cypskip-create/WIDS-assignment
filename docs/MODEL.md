# Model design and executed validation

Random Forest combines many decision trees trained on different sampled observations and feature subsets. It handles nonlinear relations between rates, proportions and radio measurements without requiring feature scaling. Parameters: 160 trees for stable voting, maximum depth 12 and minimum leaf size 2 to limit memorization, balanced class weights for minority malicious observations, seed 42 for reproducibility. These parameters were fixed before inspecting holdout performance; no test-driven tuning was performed.

Median imputation is fitted only to training data and serialized with the forest. Missing indicators identify absent fields. An all-missing input remains a retained feature. Inference validates feature names/version and window/step, and accepts arbitrary dictionary order only by reordering to the canonical allowlist. Confidence is the forest's uncalibrated P(malicious). A binary classifier does not establish an attack category. The deauthentication flood category comes from the measured rate rule.

## Feature schema: 80211-window-v2

All 18 extracted measurements are per observed transmitter/BSSID, at each event-time snapshot. Rates use the configured 5-second duration even for warmup/final partial windows. No MAC is a predictive input. The classifier uses 16 of these measurements: RSSI mean and variability are analysis-only because the publisher CSV and Scapy select different antenna namespaces. A matched 2,000-packet PCAP/CSV comparison produced 302 observations with zero differences across all 16 predictive features (reports/feature_compatibility.json). Signal coverage agrees and is retained. Inference discards the two analysis-only signal values identically to training.

| Feature | Meaning |
|---|---|
| total_frames | Number of included raw frames |
| frames_per_second | Total divided by window seconds |
| management_per_second | Management frames divided by duration |
| deauth_count | Type 0/subtype 12 frames |
| deauth_per_second | Deauth count divided by duration |
| disassoc_count | Type 0/subtype 10 count |
| beacon_count | Type 0/subtype 8 count |
| auth_count | Type 0/subtype 11 count |
| probe_request_count | Type 0/subtype 4 count |
| deauth_ratio | Deauth divided by total |
| distinct_destinations | Count of nonmissing receiver addresses |
| retry_ratio | Frames with retry flag divided by total |
| mean_frame_size | Mean captured frame bytes |
| mean_rssi | Mean available Radiotap signal, NaN if absent |
| std_rssi | Population standard deviation of available RSSI |
| rssi_coverage | Fraction of frames with signal metadata |
| broadcast_ratio | Receiver group-address bit fraction (broadcast or multicast) |
| reason7_ratio | Deauth frames with reason 7 divided by all deauth frames |

## Holdout

All CSV segments belong to one recording. The pipeline uses 60-second temporal blocks with the first five seconds of eligible windows removed at every boundary, then GroupShuffleSplit(test_size=0.3, random_state=42) on block IDs. Block proportions do not imply an exact 30% row split because blocks have different numbers of transmitter groups. Shared packets cannot span retained blocks. Training groups and test groups are saved verbatim. No timestamps, MACs, label-like columns, source identity or original attack label enter X.

Actual execution: 3,484 training and 2,802 test windows, from 6,286 retained observations. Test support: 2,657 normal and 145 malicious. Actual matrix rows (truth) and columns (prediction), both Normal then Malicious:

| | Predicted normal | Predicted malicious |
|---|---:|---:|
| Actual normal | 2645 | 12 |
| Actual malicious | 2 | 143 |

Accuracy 0.9950035689; precision 0.9225806452; recall 0.9862068966; F1 0.9533333333; ROC-AUC 0.9992732275. Twelve false positives could cause unnecessary investigations. Two malicious windows were missed in this holdout; future captures may produce additional false negatives. Recall measures detected labeled attack windows, not number of attack events or affected devices. Overlapping windows within a block mean support is correlated.

1,984 duplicate feature rows exist in the full table; 1,023 test rows have identical feature values to at least one training row. They are temporally separated observations rather than shared packets, but repetition can inflate apparent performance. Single-radio RSSI/frame-size fingerprints and within-run similarity also limit generalization. No independent-session score, calibrated confidence, broad attack taxonomy, confidence interval or throughput guarantee is claimed. A future independent recording should be reserved completely for final evaluation, with repeated-session grouped validation during model development.

Feature importance is computed from the actual fitted imputer representation including missing indicators. Impurity importance can favor correlated features and should not be read as causality. `reports/evaluation.json` records exact library versions, parameters, group IDs, metrics and provenance. `reports/predictions.csv` contains actual versus predicted test labels. No synthetic fixture contributes to these reported results.
