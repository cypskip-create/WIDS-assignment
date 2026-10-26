import json
import logging
import uuid


class AlertManager:
    def __init__(self, settings):
        self.settings = settings
        self.last = {}

    def create(self, session_id, observation, decision):
        now = observation.timestamp
        # Bounded cooldown state, using capture time for deterministic replay.
        self.last = {k: t for k, t in self.last.items() if now-t < self.settings.cooldown_seconds}
        if decision.source == "none":
            return None
        category = "Deauthentication flood" if decision.rule_fired else "ML-predicted malicious traffic"
        key = (observation.transmitter, observation.bssid, category)
        if key in self.last:
            return None
        self.last[key] = now
        rate = observation.features["deauth_per_second"]
        severity = "Critical" if rate >= self.settings.deauth_threshold*self.settings.critical_multiplier else "High" if decision.rule_fired else "Medium"
        logging.getLogger(__name__).warning("alert category=%s source=%s", category, decision.source)
        return dict(id=str(uuid.uuid4()), session_id=session_id, timestamp=now, category=category,
                    severity=severity, source=decision.source, transmitter=observation.transmitter,
                    destination=observation.destination, bssid=observation.bssid,
                    frame_count=int(observation.features["total_frames"]), deauth_rate=rate,
                    ml_prediction=decision.ml_prediction, confidence=decision.confidence,
                    explanation=decision.explanation, status="New", evidence=json.dumps(observation.features))
