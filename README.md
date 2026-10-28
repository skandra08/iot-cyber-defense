# IoT Cyber Defense lab

Build, attack and defend a simulated hydroponic IoT pipeline (pH, EC, temperature, flow
sensors -> MQTT broker -> anomaly detector). Everything runs on localhost.

```
sensor.py ──publish──▶ Mosquitto ──subscribe──▶ detector.py ──▶ results/*.alerts.jsonl
                          ▲
        attacks/spoof.py, attacks/replay.py   (the "red team")
```

## Run it

```bash
brew install mosquitto                      # once
python3 -m venv .venv && .venv/bin/pip install paho-mqtt numpy
.venv/bin/python tests/test_detector.py     # detector unit tests
.venv/bin/python run_demo.py                # ~1 min: certs, broker, 3 scenarios, scoreboard
```

`run_demo.py` generates a private CA and per-device certs, starts one broker with three
listeners, and runs identical sensors + attacks against each:

| Mode  | Port | Posture                                   |
|-------|------|-------------------------------------------|
| plain | 1883 | no encryption, anonymous                  |
| tls   | 8884 | encrypted, server-auth only, anonymous    |
| mtls  | 8883 | client certs required + per-device ACL    |

## Pieces

- `sensor.py` – 3 pumps publishing `farm/<device>/telemetry` (mean-reverting random walk, seq + ts).
- `detector.py` – range, seq replay/gap, timestamp skew and rolling z-score checks. Flagged
  messages never update baselines, so injected data can't poison the model.
- `attacks/spoof.py` – forged telemetry (blatant, or subtle with sniffed seq numbers).
- `attacks/replay.py` – sniff then re-publish captured traffic.
- `certs/gen_certs.sh`, `broker/` – CA, device certs, broker config, ACL.
- `docs/SECURITY_REPORT.md`, `docs/RUNBOOK.md` – the deliverables.

Attack payloads carry a `_gt` label used only to score the detector; it never influences decisions.
The lab keys are throwaway and git-ignored. Only attack systems you own.
