from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline


def build_pipeline(seed=42):
    return Pipeline([("imputer", SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True)),
                     ("classifier", RandomForestClassifier(n_estimators=160, max_depth=12, min_samples_leaf=2,
                                                          class_weight="balanced", random_state=seed, n_jobs=-1))])
