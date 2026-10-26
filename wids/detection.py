from dataclasses import dataclass


@dataclass
class Decision:
    rule_fired: bool
    ml_prediction: int | None
    confidence: float | None
    source: str
    explanation: str


class Detector:
    def __init__(self, settings, model=None):
        self.settings, self.model = settings, model

    def evaluate(self, observation):
        rate = observation.features["deauth_per_second"]
        rule = rate >= self.settings.deauth_threshold and observation.features["deauth_count"] >= 2
        prediction = confidence = None
        if self.model:
            prediction, confidence = self.model.predict(observation.features)
        source = "both" if rule and prediction == 1 else "rule" if rule else "ml" if prediction == 1 else "none"
        explanation = f"{int(observation.features['deauth_count'])} deauthentication frames / {self.settings.window_seconds:g}s = {rate:.2f} fps; threshold {self.settings.deauth_threshold:g} fps."
        if prediction is not None:
            explanation += f" ML: {'malicious' if prediction else 'normal'} (P(malicious)={confidence:.3f})."
            if rule and prediction == 0:
                explanation += " Rule / ML disagreement retained."
        else:
            explanation += " ML unavailable; rule-based detection only."
        return Decision(rule, prediction, confidence, source, explanation)
