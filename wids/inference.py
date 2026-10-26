from pathlib import Path
import joblib
import pandas as pd
from .feature_extractor import FEATURES, MODEL_FEATURES, SCHEMA_VERSION


class Model:
    def __init__(self, path, window_seconds=None, step_seconds=None):
        # Local trusted artifacts only: joblib is executable serialization.
        bundle = joblib.load(Path(path))
        self.pipeline, self.metadata = bundle["pipeline"], bundle["metadata"]
        # Tiny single-window predictions are faster without spawning a job pool
        # for every forest call. Training remains parallel.
        self.pipeline.named_steps["classifier"].n_jobs = 1
        if self.metadata["schema_version"] != SCHEMA_VERSION or self.metadata["features"] != FEATURES or self.metadata.get("predictive_features") != MODEL_FEATURES:
            raise ValueError("Model feature schema is incompatible")
        for name, value in (("window_seconds", window_seconds), ("step_seconds", step_seconds)):
            if value is not None and self.metadata[name] != value:
                raise ValueError(f"Model {name} does not match monitoring configuration")

    def predict(self, features):
        if set(features) != set(FEATURES):
            raise ValueError("Inference feature names do not match the canonical schema")
        frame = pd.DataFrame([[features[k] for k in MODEL_FEATURES]], columns=MODEL_FEATURES)
        prediction = int(self.pipeline.predict(frame)[0])
        classes = list(self.pipeline.classes_)
        return prediction, float(self.pipeline.predict_proba(frame)[0][classes.index(1)])
