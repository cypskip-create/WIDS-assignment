from dataclasses import dataclass
import math
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, RadioTap

MANAGEMENT_NAMES = {0: "Association request", 1: "Association response", 2: "Reassociation request", 3: "Reassociation response", 4: "Probe request", 5: "Probe response", 8: "Beacon", 10: "Disassociation", 11: "Authentication", 12: "Deauthentication"}


@dataclass(frozen=True)
class Frame:
    timestamp: float
    type: int
    subtype: int
    transmitter: str | None
    destination: str | None
    bssid: str | None
    length: int
    rssi: float | None = None
    frequency: int | None = None
    reason: int | None = None
    retry: bool = False
    multicast: bool = False
    label: str | None = None

    @property
    def name(self):
        return MANAGEMENT_NAMES.get(self.subtype, "Management") if self.type == 0 else {1: "Control", 2: "Data"}.get(self.type, "Extension")


def is_multicast(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 1)
    except (ValueError, AttributeError):
        return False


def parse_packet(packet) -> Frame | None:
    """Return only raw 802.11 metadata. Never infer RSSI or decrypt payloads."""
    try:
        if not packet.haslayer(Dot11):
            return None
        dot = packet[Dot11]
        timestamp = float(packet.time)
        if not math.isfinite(timestamp):
            return None
        typ, sub, flags = int(dot.type), int(dot.subtype), int(dot.FCfield)
        if typ not in (0, 1, 2, 3):
            return None
        # addr2 is the observed transmitter, not necessarily the original source.
        transmitter = dot.addr2
        bssid = dot.addr3 if typ == 0 else None
        if typ == 2:
            ds = flags & 3
            bssid = {0: dot.addr3, 1: dot.addr1, 2: dot.addr2}.get(ds)
        rssi = frequency = reason = None
        if packet.haslayer(RadioTap):
            rt = packet[RadioTap]
            signal = getattr(rt, "dBm_AntSignal", None)
            if signal is not None and math.isfinite(float(signal)):
                rssi = float(signal)
            frequency = getattr(rt, "ChannelFrequency", None)
        if typ == 0 and sub == 12 and packet.haslayer(Dot11Deauth):
            reason = int(packet[Dot11Deauth].reason)
        elif typ == 0 and sub == 10 and packet.haslayer(Dot11Disas):
            reason = int(packet[Dot11Disas].reason)
        return Frame(timestamp, typ, sub, transmitter, dot.addr1, bssid, len(packet), rssi, frequency, reason, bool(flags & 8), is_multicast(dot.addr1))
    except (ValueError, TypeError, AttributeError, IndexError, OverflowError):
        return None
