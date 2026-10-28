"""Simulated hydroponic sensor fleet publishing telemetry over MQTT."""
import argparse
import random
import time

from common import DEVICES, TELEMETRY_TOPIC, connect, dumps, make_client

SETPOINT = {"ph": 6.0, "ec": 1.8, "temp_c": 22.0, "flow_lpm": 2.0}
NOISE = {"ph": 0.03, "ec": 0.02, "temp_c": 0.15, "flow_lpm": 0.05}


class Device:
    def __init__(self, device_id):
        self.id = device_id
        self.seq = 0
        self.state = dict(SETPOINT)

    def reading(self):
        self.seq += 1
        for key, target in SETPOINT.items():
            # mean-reverting random walk
            self.state[key] += 0.2 * (target - self.state[key]) + random.gauss(0, NOISE[key])
        return {"device_id": self.id, "seq": self.seq, "ts": time.time(),
                **{k: round(v, 3) for k, v in self.state.items()}, "_gt": "legit"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["plain", "tls", "mtls"], default="plain")
    ap.add_argument("--interval", type=float, default=0.2)
    ap.add_argument("--duration", type=float, default=30)
    args = ap.parse_args()

    devices, clients = [], {}
    for dev_id in DEVICES:
        client = make_client(args.mode, dev_id, cert_as=dev_id)
        ok, why = connect(client, args.mode)
        if not ok:
            raise SystemExit(f"{dev_id}: {why}")
        devices.append(Device(dev_id))
        clients[dev_id] = client

    end = time.time() + args.duration
    while time.time() < end:
        for dev in devices:
            clients[dev.id].publish(TELEMETRY_TOPIC.format(device=dev.id), dumps(dev.reading()))
        time.sleep(args.interval)
    for client in clients.values():
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
