"""Event-time, half-open (end - window, end] rolling windows.

Snapshots occur immediately before an incoming packet at/after a scheduled tick.
Frames exactly on a tick are included at the next tick; the lower edge is excluded.
Memory ceilings fail explicitly rather than silently changing feature semantics.
"""
from collections import deque
from dataclasses import dataclass
from .feature_extractor import extract_features


@dataclass
class Observation:
    timestamp: float
    transmitter: str | None
    bssid: str | None
    destination: str | None
    features: dict
    labels: tuple[str, ...] = ()


class WindowAggregator:
    def __init__(self, settings):
        self.settings = settings
        self.groups = {}
        self.next_tick = None
        self.last_timestamp = None
        self.buffered = 0

    def _snapshot(self, end):
        output = []
        for key in list(self.groups):
            frames = self.groups[key]
            while frames and frames[0].timestamp <= end-self.settings.window_seconds:
                frames.popleft()
                self.buffered -= 1
            if not frames:
                del self.groups[key]
                continue
            output.append(Observation(end, *key, frames[-1].destination,
                                      extract_features(frames, self.settings.window_seconds),
                                      tuple(f.label for f in frames if f.label is not None)))
        return output

    def push(self, frame):
        if self.last_timestamp is not None and frame.timestamp < self.last_timestamp:
            raise ValueError("Capture timestamps are out of order; sort the source before ingestion")
        output = []
        if self.next_tick is None:
            self.next_tick = frame.timestamp + self.settings.step_seconds
        while self.next_tick <= frame.timestamp:
            output.extend(self._snapshot(self.next_tick))
            self.next_tick += self.settings.step_seconds
            if not self.groups and self.next_tick < frame.timestamp:
                # Do not iterate millions of empty ticks across recording gaps.
                steps = int((frame.timestamp-self.next_tick)//self.settings.step_seconds)
                self.next_tick += steps*self.settings.step_seconds
        key = (frame.transmitter, frame.bssid)
        if key not in self.groups:
            if len(self.groups) >= self.settings.max_groups:
                raise RuntimeError("Observation group memory ceiling reached")
            self.groups[key] = deque()
        if self.buffered >= self.settings.max_frames:
            raise RuntimeError("Frame memory ceiling reached; reduce the window or increase the explicit limit")
        self.groups[key].append(frame)
        self.buffered += 1
        self.last_timestamp = frame.timestamp
        return output

    def flush(self):
        if self.last_timestamp is None:
            return []
        output = self._snapshot(self.last_timestamp + 0.000001)
        self.groups.clear()
        self.buffered = 0
        return output
