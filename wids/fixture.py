"""Generate valid synthetic wireless frames to disk ONLY. No radio transmission."""
from pathlib import Path
import json
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11ProbeReq, Dot11Auth
from scapy.utils import PcapWriter


def generate_fixture(path="data/demo/synthetic_deauth.pcap"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    ap, destination = "02:00:00:00:00:01", "ff:ff:ff:ff:ff:ff"
    total = 0
    with PcapWriter(str(path), linktype=127, sync=True) as writer:
        for second in range(50):
            # 0-14 normal, 15-24 occasional deauth, 25-34 flood, 35-49 recovery.
            count = 100 if 25 <= second < 35 else 8
            for index in range(count):
                deauth = 25 <= second < 35 or (second in (16, 21) and index == 0)
                subtype = 12 if deauth else [8, 8, 4, 11][index % 4]
                body = Dot11Deauth(reason=7) if deauth else Dot11Beacon()/Dot11Elt(ID="SSID", info=b"Sentinel-SYNTHETIC") if subtype == 8 else Dot11ProbeReq()/Dot11Elt(ID="SSID", info=b"") if subtype == 4 else Dot11Auth(seqnum=1)
                packet = RadioTap(present="Channel+dBm_AntSignal", ChannelFrequency=2412, ChannelFlags=0x00a0, dBm_AntSignal=-48)/Dot11(type=0, subtype=subtype, addr1=destination, addr2=ap, addr3=ap, SC=(total % 4096)*16)/body
                packet.time = 1700000000+second+index/count
                writer.write(packet)
                total += 1
    path.with_suffix(".json").write_text(json.dumps(dict(provenance="synthetic", packets=total,
        purpose="Parser, replay and detector software testing only; never evidence of real-world ML performance", segments={"normal": [0, 15], "occasional_deauth": [15, 25], "flood": [25, 35], "recovery": [35, 50]}), indent=2), encoding="utf-8")
    return path
