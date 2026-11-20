"""RandomForest model, trained at runtime from data/training_urls.csv.

The model only sees lexical URL features, so it can score a URL even
when the page itself cannot be fetched.
"""
from __future__ import annotations

import csv
import os

from sklearn.ensemble import RandomForestClassifier

from .url_features import extract_url_features, feature_vector

_MODEL = None
_TRAINING_CSV = os.path.join(
    os.path.dirname(__file__), "..", "data", "training_urls.csv"
)


def _load_training_rows(path: str | None = None) -> tuple[list, list]:
    path = path or _TRAINING_CSV
    X, y = [], []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            url = (row.get("url") or "").strip()
            label = (row.get("label") or "").strip()
            if not url or label not in ("0", "1"):
                continue
            X.append(feature_vector(extract_url_features(url)))
            y.append(int(label))
    return X, y


class PhishingModel:
    """A RandomForest trained on the bundled labeled URL examples."""

    def __init__(self, csv_path: str | None = None):
        X, y = _load_training_rows(csv_path)
        if len(set(y)) < 2:
            raise ValueError("training data needs both classes (0 and 1)")
        self.clf = RandomForestClassifier(n_estimators=100, random_state=42)
        self.clf.fit(X, y)
        self.n_samples = len(y)

    def phishing_probability(self, url_or_features) -> float:
        """Probability (0.0-1.0) that the URL is phishing."""
        if isinstance(url_or_features, str):
            feats = extract_url_features(url_or_features)
        else:
            feats = url_or_features
        proba = self.clf.predict_proba([feature_vector(feats)])[0]
        idx = list(self.clf.classes_).index(1)
        return float(proba[idx])


def get_model() -> PhishingModel:
    """The shared model instance (trained once, reused afterwards)."""
    global _MODEL
    if _MODEL is None:
        _MODEL = PhishingModel()
    return _MODEL
