from dataclasses import asdict, dataclass
import math


@dataclass(frozen=True)
class Settings:
    window_seconds: float = 5.0
    step_seconds: float = 1.0
    deauth_threshold: float = 10.0
    cooldown_seconds: float = 30.0
    critical_multiplier: float = 5.0
    replay_speed: float = 1.0
    refresh_seconds: float = 2.0
    retention_days: int = 30
    interface: str = ""
    model_path: str = "models/random_forest.joblib"
    max_frames: int = 100000
    max_groups: int = 4096

    def __post_init__(self):
        for name in ("window_seconds", "step_seconds", "deauth_threshold", "critical_multiplier", "replay_speed", "refresh_seconds"):
            value = getattr(self, name)
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        if self.step_seconds > self.window_seconds:
            raise ValueError("Step cannot exceed observation window")
        if not math.isfinite(self.cooldown_seconds) or self.cooldown_seconds < 0:
            raise ValueError("Cooldown must be finite and nonnegative")
        if self.retention_days < 1 or self.max_frames < 1 or self.max_groups < 1:
            raise ValueError("Retention and memory limits must be positive")

    def to_dict(self):
        return asdict(self)
