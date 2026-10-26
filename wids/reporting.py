import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from .storage import csv_export


def evaluation_charts(metadata, output):
    output = Path(output)
    matrix = np.array(metadata["metrics"]["confusion_matrix"])
    fig, ax = plt.subplots(figsize=(6, 4.5), constrained_layout=True)
    ax.imshow(matrix, cmap="Blues")
    for (i, j), value in np.ndenumerate(matrix):
        ax.text(j, i, str(value), ha="center", va="center", fontsize=20,
                color="white" if value > matrix.max()/2 else "#152539")
    ax.set(xticks=[0, 1], yticks=[0, 1], xticklabels=["Normal", "Malicious"], yticklabels=["Normal", "Malicious"], xlabel="Predicted label", ylabel="Actual label", title="Held-out confusion matrix")
    fig.savefig(output/"confusion_matrix.png", dpi=180)
    plt.close(fig)
    importance = sorted(metadata["feature_importance"].items(), key=lambda x: x[1])[-10:]
    fig, ax = plt.subplots(figsize=(8, 5), constrained_layout=True)
    ax.barh([x[0] for x in importance], [x[1] for x in importance], color="#078f9e")
    ax.set(xlabel="Impurity-based importance", title="Fitted Random Forest features")
    fig.savefig(output/"feature_importance.png", dpi=180)
    plt.close(fig)


def export_report(storage, output="reports"):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for table in ("sessions", "incidents", "observations", "events"):
        (output/f"{table}.csv").write_text(csv_export(storage.rows(f"SELECT * FROM {table}")), encoding="utf-8")
    summary = {"sessions": storage.rows("SELECT * FROM sessions"), "incidents": storage.rows("SELECT * FROM incidents"), "note": "Capture timestamps are UTC epoch; provenance recorded per session. MACs are observed addresses, not verified identities."}
    (output/"monitoring_report.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return output
