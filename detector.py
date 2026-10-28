"""Anomaly detector: subscribes to all telemetry and flags suspicious messages.

Checks (per device):
  out_of_range  value outside physical limits
  seq_replay    seq not greater than the last accepted seq (duplicate / replay)
  seq_gap       seq jumps far ahead of the last accepted seq (injection)
  stale_ts      timestamp too far from the detector's clock
  zscore        value > Z_LIMIT sigmas from the device's rolling baseline
Flagged messages never update the baseline or seq state, so an attacker can't
poison the model by injecting a few messages. The '_gt' ground-truth label in
payloads is used only for scoring, never for decisions.
"""
import argparse
import json
import statistics
import time
from collections import Counter, defaultdict, deque

from common import connect, make_client

LIMITS = {"ph": (4.0, 9.0), "ec": (0.5, 4.0), "temp_c": (10.0, 35.0), "flow_lpm": (0.0, 10.0)}
WINDOW, MIN_SAMPLES, Z_LIMIT = 40, 15, 5.0
MAX_SEQ_GAP, MAX_CLOCK_SKEW = 5, 5.0


class Detector:
    def __init__(self):
        self.last_seq = {}
        self.history = defaultdict(lambda: defaultdict(lambda: deque(maxlen=WINDOW)))

    def check(self, msg, now=None):
        """Return a list of alert names (empty list = message accepted)."""
        now = time.time() if now is None else now
        dev = msg.get("device_id")
        alerts = []
        if not dev or any(k not in msg for k in (*LIMITS, "seq", "ts")):
            return ["malformed"]

        for key, (lo, hi) in LIMITS.items():
            if not lo <= msg[key] <= hi:
                alerts.append("out_of_range")
                break
        if abs(now - msg["ts"]) > MAX_CLOCK_SKEW:
            alerts.append("stale_ts")
        last = self.last_seq.get(dev)
        if last is not None:
            if msg["seq"] <= last:
                alerts.append("seq_replay")
            elif msg["seq"] - last > MAX_SEQ_GAP:
                alerts.append("seq_gap")
        for key in LIMITS:
            hist = self.history[dev][key]
            if len(hist) >= MIN_SAMPLES:
                std = max(statistics.pstdev(hist), 1e-3)
                if abs(msg[key] - statistics.fmean(hist)) / std > Z_LIMIT:
                    alerts.append("zscore")
                    break

        if not alerts:
            self.last_seq[dev] = msg["seq"]
            for key in LIMITS:
                self.history[dev][key].append(msg[key])
        return alerts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["plain", "tls", "mtls"], default="plain")
    ap.add_argument("--duration", type=float, default=30)
    ap.add_argument("--out", default="results/detector.json")
    args = ap.parse_args()

    det = Detector()
    stats = {"seen": Counter(), "flagged": Counter(), "alert_types": defaultdict(Counter)}
    alert_log = open(args.out.replace(".json", ".alerts.jsonl"), "w")

    def on_message(client, userdata, message):
        msg = json.loads(message.payload)
        gt = msg.get("_gt", "unknown")
        alerts = det.check(msg)
        stats["seen"][gt] += 1
        if alerts:
            stats["flagged"][gt] += 1
            for a in alerts:
                stats["alert_types"][gt][a] += 1
            alert_log.write(json.dumps({"t": time.time(), "alerts": alerts, "msg": msg}) + "\n")

    client = make_client(args.mode, "detector", cert_as="detector")
    client.on_message = on_message
    ok, why = connect(client, args.mode)
    if not ok:
        raise SystemExit(f"detector: {why}")
    client.subscribe("farm/+/telemetry")
    time.sleep(args.duration)
    client.loop_stop()
    alert_log.close()
    with open(args.out, "w") as fh:
        json.dump({k: ({g: dict(c) for g, c in v.items()} if k == "alert_types" else dict(v))
                   for k, v in stats.items()}, fh, indent=2)


if __name__ == "__main__":
    main()
