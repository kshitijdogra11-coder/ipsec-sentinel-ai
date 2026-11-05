"""Analyzer accuracy tests against testbed ground truth."""
import os

import pytest

from app.analyzer.ike_parser import parse_ike
from app.analyzer.pcap_reader import CaptureFormatError, read_packets
from app.analyzer.pipeline import analyze_file
from app.testbed.generator import preset, generate_capture


@pytest.fixture(scope="module")
def tmpdir(tmp_path_factory):
    return tmp_path_factory.mktemp("caps")


CASES = [
    ("cnsa-suite-b", "video", {"mode": "tunnel", "fam": "AES-GCM", "ike": "IKEv2", "pfs": True, "grade": "A"}),
    ("legacy-ikev1-main", "whatsapp", {"mode": "tunnel", "fam": "3DES", "ike": "IKEv1", "pfs": False, "grade": "F"}),
    ("host-to-host-transport", "email", {"mode": "transport", "fam": "AES-CBC", "ike": "IKEv2"}),
    ("null-encryption", "web", {"mode": "tunnel", "fam": "NULL", "ike": "IKEv2", "grade": "F"}),
]


@pytest.mark.parametrize("name,traffic,exp", CASES)
def test_identification(tmpdir, name, traffic, exp):
    path = os.path.join(tmpdir, f"{name}.pcap")
    generate_capture(preset(name, traffic=traffic, duration=100, seed=42), path)
    r = analyze_file(path)
    t = r["tunnels"][0]
    idn = t["identification"]
    assert idn["mode"]["value"] == exp["mode"]
    assert str(idn["encryption"]["value"]).startswith(exp["fam"])
    assert idn["ike_version"]["value"] == exp["ike"]
    assert idn["traffic_type"]["value"] == traffic
    if "pfs" in exp:
        assert idn["pfs"]["value"] is exp["pfs"]
    if "grade" in exp:
        assert r["assessment"]["grade"] == exp["grade"]


def test_aggressive_mode_is_critical(tmpdir):
    path = os.path.join(tmpdir, "aggr.pcap")
    generate_capture(preset("insecure-aggressive-psk", traffic="icmp", duration=60, seed=1), path)
    r = analyze_file(path)
    ids = {f["id"] for f in r["assessment"]["tunnels"][0]["findings"]}
    assert {"IPS-061", "IPS-020", "MX-04"} <= ids
    assert r["tunnels"][0]["ike"]["identities"]


def test_replay_detection(tmpdir):
    path = os.path.join(tmpdir, "replay.pcap")
    truth = generate_capture(preset("enterprise-default", traffic="web", duration=100, seed=7, replay_attack=True), path)
    r = analyze_file(path)
    assert r["tunnels"][0]["replay"]["duplicates"] == truth["replayed_packets"] > 0


def test_ah_mode_from_next_header(tmpdir):
    path = os.path.join(tmpdir, "ah.pcap")
    generate_capture(preset("ah-integrity-only", traffic="voip", duration=60, seed=3), path)
    r = analyze_file(path)
    assert r["tunnels"][0]["protocol"] == "AH"
    assert r["tunnels"][0]["identification"]["mode"]["confidence"] >= 0.99


def test_rejects_non_pcap(tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    with pytest.raises(CaptureFormatError):
        list(read_packets(str(p)))


def test_truncated_ike_does_not_crash():
    assert parse_ike(b"\x00" * 10) is None
    hdr = b"A" * 8 + b"\x00" * 8 + bytes([33, 0x20, 34, 8]) + b"\x00\x00\x00\x00" + (500).to_bytes(4, "big")
    m = parse_ike(hdr + b"\x00\x00\xff\xff")  # payload length overruns buffer
    assert m is not None and m.get("malformed")
