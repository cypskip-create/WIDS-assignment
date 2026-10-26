from dataclasses import replace
import math
import pytest
from wids.config import Settings
from wids.packet_parser import Frame
from wids.feature_extractor import FEATURES, extract_features
from wids.window_aggregator import WindowAggregator, Observation
from wids.detection import Detector
from wids.alerts import AlertManager


def frame(t=0, subtype=12, **kwargs):
    return Frame(t, 0, subtype, "source", "destination", "bssid", 40, **kwargs)


def observation(count=100, end=5):
    return Observation(end, "source", "bssid", "destination", extract_features([frame(i/100) for i in range(count)], 5))


def test_rates_order_and_missing():
    values = extract_features([frame(), frame(subtype=8)], 5)
    assert list(values) == FEATURES
    assert values["frames_per_second"] == .4
    assert values["deauth_count"] == 1 and values["deauth_per_second"] == .2
    assert math.isnan(values["mean_rssi"]) and values["rssi_coverage"] == 0


def test_window_boundaries_and_memory_cleanup():
    agg = WindowAggregator(Settings(window_seconds=5, step_seconds=1))
    assert agg.push(frame(0)) == []
    values = agg.push(frame(5))
    assert values[-1].timestamp == 4  # t=0 excluded at end=5; incoming t=5 not added yet
    assert values[-1].features["total_frames"] == 1
    result = agg.push(frame(6))
    assert result[0].features["total_frames"] == 1
    agg.push(frame(1000000))
    assert agg.buffered == 1
    assert len(agg.groups) == 1
    with pytest.raises(ValueError, match="out of order"):
        agg.push(frame(1))


def test_explicit_memory_limit():
    agg = WindowAggregator(Settings(max_frames=1))
    agg.push(frame(0))
    with pytest.raises(RuntimeError, match="memory ceiling"):
        agg.push(frame(.1))


def test_rule_normal_isolated_burst_and_cooldown():
    settings = Settings()
    detector, alerts = Detector(settings), AlertManager(settings)
    normal = Observation(5, "s", "b", "d", extract_features([frame(subtype=8)], 5))
    assert detector.evaluate(normal).source == "none"
    assert detector.evaluate(observation(1)).source == "none"
    burst = observation()
    decision = detector.evaluate(burst)
    assert decision.rule_fired and decision.ml_prediction is None and decision.source == "rule"
    assert alerts.create("session", burst, decision)
    assert alerts.create("session", replace(burst, timestamp=10), decision) is None
    assert alerts.create("session", replace(burst, timestamp=35), decision)


@pytest.mark.parametrize("prediction,expected", [(0, "rule"), (1,"both")])
def test_rule_ml_disagreement(prediction, expected):
    class FakeModel:
        def predict(self, features):
            return prediction, .9 if prediction else .1
    result = Detector(Settings(), FakeModel()).evaluate(observation())
    assert result.source == expected and result.ml_prediction == prediction
    assert ("disagreement" in result.explanation) == (prediction == 0)


@pytest.mark.parametrize("changes", [{"window_seconds":0}, {"step_seconds":6}, {"deauth_threshold":float("nan")}, {"cooldown_seconds":-1}])
def test_settings_validation(changes):
    with pytest.raises(ValueError):
        Settings(**changes)
