from datetime import datetime, timezone
import importlib.metadata
import json
import logging
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from .feature_extractor import FEATURES, MODEL_FEATURES, SCHEMA_VERSION
from .preprocessing import build_pipeline


def train(csv_path, model_path="models/random_forest.joblib", report_dir="reports", seed=42):
    data = pd.read_csv(csv_path)
    metadata = json.loads(Path(str(csv_path)+".json").read_text(encoding="utf-8"))
    if metadata["features"] != FEATURES or metadata["schema_version"] != SCHEMA_VERSION:
        raise ValueError("Training feature schema mismatch")
    if not set(FEATURES+["group", "label"]).issubset(data.columns):
        raise ValueError("Prepared canonical features, group and label are required")
    if set(data.label.unique()) != {0, 1}:
        raise ValueError("Training requires normal and malicious labels")
    if data.group.nunique() < 4:
        raise ValueError("At least four independent sessions or purged temporal blocks are required")
    # One fixed split; no repeated attempts selected by favorable test labels.
    train_idx, test_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=seed).split(data, groups=data.group))
    training, testing = data.iloc[train_idx], data.iloc[test_idx]
    if training.label.nunique() != 2 or testing.label.nunique() != 2:
        raise ValueError("Fixed holdout lacks both classes; acquire more independent labeled data rather than selecting a favorable split")
    pipeline = build_pipeline(seed)
    xtrain, xtest = training[MODEL_FEATURES], testing[MODEL_FEATURES]
    pipeline.fit(xtrain, training.label)
    predicted = pipeline.predict(xtest)
    probabilities = pipeline.predict_proba(xtest)[:, list(pipeline.classes_).index(1)]
    actual = testing.label
    metrics = dict(accuracy=float(accuracy_score(actual, predicted)), precision=float(precision_score(actual, predicted, zero_division=0)),
                   recall=float(recall_score(actual, predicted, zero_division=0)), f1=float(f1_score(actual, predicted, zero_division=0)),
                   roc_auc=float(roc_auc_score(actual, probabilities)), confusion_matrix=confusion_matrix(actual, predicted, labels=[0, 1]).tolist(),
                   support={"normal": int((actual == 0).sum()), "malicious": int((actual == 1).sum())})
    feature_names = list(pipeline.named_steps["imputer"].get_feature_names_out(MODEL_FEATURES))
    fitted = pipeline.named_steps["classifier"]
    # Exact duplicate feature rows across partitions are an explicitly reported risk.
    train_hashes = set(pd.util.hash_pandas_object(xtrain, index=False))
    duplicate_test = int(pd.util.hash_pandas_object(xtest, index=False).isin(train_hashes).sum())
    metadata.update(algorithm="RandomForestClassifier", predictive_features=MODEL_FEATURES,
                    excluded_analysis_features={"mean_rssi": "Publisher/Scapy antenna namespace mismatch", "std_rssi": "Publisher/Scapy antenna namespace mismatch"},
                    trained_at=datetime.now(timezone.utc).isoformat(),
                    seed=seed, class_mapping={"0": "Normal", "1": "Malicious"},
                    train_samples=len(training), test_samples=len(testing),
                    train_groups=sorted(training.group.unique()), test_groups=sorted(testing.group.unique()),
                    evaluation_method=metadata.get("split_design", "Group-disjoint holdout"),
                    metrics=metrics, duplicate_test_features_seen_in_training=duplicate_test,
                    parameters={k: fitted.get_params()[k] for k in ("n_estimators", "max_depth", "min_samples_leaf", "class_weight", "random_state")},
                    feature_importance=dict(zip(feature_names, fitted.feature_importances_.tolist(), strict=True)),
                    versions={p: importlib.metadata.version(p) for p in ("scikit-learn", "numpy", "pandas", "joblib")})
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(dict(pipeline=pipeline, metadata=metadata), model_path)
    Path(str(model_path)+".json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    output = Path(report_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output/"evaluation.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    testing[[c for c in ("timestamp", "group", "label", "original_labels") if c in testing]].assign(prediction=predicted, probability_malicious=probabilities).to_csv(output/"predictions.csv", index=False)
    from .reporting import evaluation_charts
    evaluation_charts(metadata, output)
    logging.getLogger(__name__).info("training completed metrics=%s", metrics)
    return metadata
