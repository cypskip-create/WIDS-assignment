import json
import numpy as np
import pandas as pd
import pytest
from wids.dataset import map_label, prepare_csv
from wids.feature_extractor import FEATURES, MODEL_FEATURES, SCHEMA_VERSION
from wids.inference import Model
from wids.training import train


def test_label_mapping():
    assert map_label("Normal") == 0 and map_label("Deauth") == 1
    with pytest.raises(ValueError, match="Unknown label"):
        map_label("unreviewed-new-class")


def training_fixture(tmp_path):
    """Synthetic unit-test feature matrix, never a published evaluation result."""
    rng = np.random.default_rng(42)
    rows = []
    for group in range(16):
        for label in (0, 1):
            for index in range(4):
                values = dict(zip(FEATURES, rng.random(len(FEATURES))))
                values["deauth_count"] = 1 if label == 0 else 200
                values["mean_rssi"] = np.nan
                rows.append(dict(values, group=f"session-{group}", label=label, attacker_identity=label, original_labels="UNIT TEST"))
    path = tmp_path/"windows.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    meta = dict(features=FEATURES, schema_version=SCHEMA_VERSION, window_seconds=5., step_seconds=1., source="synthetic unit test", provenance="synthetic", class_distribution={"0":64,"1":64}, split_design="Independent synthetic test groups")
    (tmp_path/"windows.csv.json").write_text(json.dumps(meta))
    return path


def test_training_metrics_save_load_schema_and_isolation(tmp_path):
    path = training_fixture(tmp_path)
    model_path = tmp_path/"model.joblib"
    meta = train(path, model_path, tmp_path/"reports")
    assert not set(meta["train_groups"]) & set(meta["test_groups"])
    assert "attacker_identity" not in meta["features"] and "label" not in meta["features"]
    matrix = np.array(meta["metrics"]["confusion_matrix"])
    assert matrix.shape == (2,2) and matrix.sum() == meta["test_samples"]
    assert np.trace(matrix)/matrix.sum() == meta["metrics"]["accuracy"]
    model = Model(model_path, 5, 1)
    values = pd.read_csv(path)[FEATURES].iloc[0].to_dict()
    prediction, confidence = model.predict(dict(reversed(list(values.items()))))
    assert prediction in (0,1) and 0 <= confidence <= 1
    with pytest.raises(ValueError, match="feature names"):
        model.predict({"unrelated":1})
    with pytest.raises(ValueError, match="window_seconds"):
        Model(model_path, 10, 1)
    # The imputer was fitted only to the exact training rows.
    data = pd.read_csv(path)
    subset = data[data.group.isin(meta["train_groups"])][MODEL_FEATURES]
    expected = subset.median().fillna(0).to_numpy()
    np.testing.assert_allclose(model.pipeline.named_steps["imputer"].statistics_, expected)
    assert not {"mean_rssi", "std_rssi"} & set(meta["predictive_features"])
    alternate = dict(values, mean_rssi=-99, std_rssi=1000)
    assert model.predict(alternate) == model.predict(values)


def test_packet_csv_adapter_and_boundary_purge(tmp_path):
    rows = [dict(**{"frame.time_epoch": float(t), "frame.len": 40, "wlan.fc.type":0, "wlan.fc.subtype":12 if 80 <= t < 100 else 8, "Label":"Deauth" if 80 <= t < 100 else "Normal", "wlan.ta":"source", "wlan.ra":"destination", "wlan.bssid":"bssid"}) for t in range(180)]
    path = tmp_path/"packets.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    out = tmp_path/"windows.csv"
    meta = prepare_csv([path], out, provenance="synthetic")
    data = pd.read_csv(out)
    assert meta["packet_count"] == 180 and set(data.label) == {0,1}
    assert (data.timestamp % 60 >= 5).all()
    assert not any(c.startswith("wlan.") or c == "Label" for c in FEATURES)
    bad = tmp_path/"arbitrary.csv"
    pd.DataFrame({"label":[0,1],"unrelated":[1,2]}).to_csv(bad, index=False)
    with pytest.raises(ValueError, match="missing packet CSV"):
        prepare_csv([bad], out)
