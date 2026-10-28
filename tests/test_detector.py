"""Run with: .venv/bin/python tests/test_detector.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from detector import Detector  # noqa: E402

NOW = 1000.0


def msg(seq, ts=NOW, **over):
    base = {"device_id": "pump-01", "seq": seq, "ts": ts, "ph": 6.0, "ec": 1.8, "temp_c": 22.0, "flow_lpm": 2.0}
    return {**base, **over}


def warm(det, n=20):
    for i in range(1, n + 1):
        jitter = 0.01 * (i % 3)
        assert det.check(msg(i, ph=6.0 + jitter), NOW) == []
    return n


def test_clean_stream_has_no_alerts():
    warm(Detector())


def test_out_of_range():
    det = Detector()
    n = warm(det)
    assert "out_of_range" in det.check(msg(n + 1, ph=9.8), NOW)


def test_replay_and_stale():
    det = Detector()
    n = warm(det)
    alerts = det.check(msg(3, ts=NOW - 60), NOW)
    assert "seq_replay" in alerts and "stale_ts" in alerts
    assert det.check(msg(n + 1), NOW) == []  # a replay must not corrupt seq state


def test_seq_gap_does_not_poison_state():
    det = Detector()
    n = warm(det)
    assert "seq_gap" in det.check(msg(9999), NOW)
    assert det.check(msg(n + 1), NOW) == []


def test_subtle_shift_caught_by_zscore():
    det = Detector()
    n = warm(det)
    assert "zscore" in det.check(msg(n + 1, ph=6.6), NOW)


def test_malformed():
    assert Detector().check({"device_id": "x"}, NOW) == ["malformed"]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
