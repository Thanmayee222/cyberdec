# Attack pattern recognition ML models
"""
Simple RandomForest intrusion detector.
If model.pkl is missing, we auto-train on a synthetic dataset so the code
always runs (obviously: **replace with real training later**).
"""
import os, joblib, pathlib
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from utils.logger import get_logger

MODEL_PATH = pathlib.Path(__file__).with_suffix(".pkl")
log = get_logger(__name__)

class IntrusionDetector:
    def __init__(self):
        if MODEL_PATH.exists():
            self.clf = joblib.load(MODEL_PATH)
            log.info("Loaded pretrained model: %s", MODEL_PATH)
        else:
            log.warning("No model found → training dummy model...")
            self.clf = self._train_dummy()
            joblib.dump(self.clf, MODEL_PATH)

    def _train_dummy(self):
        X, y = make_classification(
            n_samples=2000, n_features=5, n_informative=3,
            n_redundant=0, flip_y=0.05, random_state=42
        )
        X_train, X_test, y_train, y_test = train_test_split(X, y,
                                                            test_size=0.2,
                                                            random_state=42)
        clf = RandomForestClassifier(n_estimators=120, random_state=42)
        clf.fit(X_train, y_train)
        log.info("Dummy model accuracy = %.2f",
                 clf.score(X_test, y_test))
        return clf

    def _extract_features(self, pkt: dict):
        """
        Returns a 5-element numeric feature list from raw JSON.
        Extend this with real packet parsing later.
        """
        payload = pkt.get("payload", "")
        url     = pkt.get("url", "")
        ip      = pkt.get("ip", "")
        return [
            len(payload),
            payload.lower().count("select"),   # crude SQL indicator
            int("/admin" in url),
            len(ip.split(".")),                # very rough…
            len(url)
        ]

    def is_intrusion(self, pkt: dict) -> bool:
        features = self._extract_features(pkt)
        return bool(self.clf.predict([features])[0])
