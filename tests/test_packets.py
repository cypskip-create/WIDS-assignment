import math
import pytest
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from wids.packet_parser import parse_packet, MANAGEMENT_NAMES


def test_deauth_and_missing_metadata():
    packet = Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2="02:00:00:00:00:01", addr3="02:00:00:00:00:01")/Dot11Deauth(reason=7)
    packet.time = 42
    frame = parse_packet(packet)
    assert frame.name == "Deauthentication" and frame.reason == 7
    assert frame.rssi is None and frame.multicast
    assert frame.timestamp == 42


@pytest.mark.parametrize("subtype", list(MANAGEMENT_NAMES))
def test_management_types(subtype):
    assert parse_packet(Dot11(type=0, subtype=subtype)).name == MANAGEMENT_NAMES[subtype]


def test_missing_addresses_and_signal():
    frame = parse_packet(Dot11(type=0, subtype=12, addr1=None, addr2=None, addr3=None))
    assert frame.transmitter is None and frame.bssid is None and not frame.multicast
    packet = RadioTap(present="dBm_AntSignal", dBm_AntSignal=-63)/Dot11(type=0, subtype=8)
    assert parse_packet(packet).rssi == -63


def test_non_wifi_and_invalid_timestamp():
    assert parse_packet(Ether()/Raw(b"ethernet")) is None
    assert parse_packet(Raw(b"bad")) is None
    packet = Dot11()
    packet.time = math.nan
    assert parse_packet(packet) is None


@pytest.mark.parametrize("flags,expected", [(0,"02:00:00:00:00:03"), (1,"02:00:00:00:00:01"), (2,"02:00:00:00:00:02"), (3,None)])
def test_data_bssid_ds_bits(flags, expected):
    frame = parse_packet(Dot11(type=2, FCfield=flags, addr1="02:00:00:00:00:01", addr2="02:00:00:00:00:02", addr3="02:00:00:00:00:03"))
    assert frame.bssid == expected
