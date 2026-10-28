# Incident Response Runbook: IoT telemetry pipeline

Alert source: `results/<mode>.alerts.jsonl` (one JSON line per flagged message: `alerts` + `msg`).

## Alert triage

| Alert | Likely cause | First action |
|-------|--------------|--------------|
| `seq_replay` (+ `stale_ts`) | Replayed capture, or device reboot/clock reset | Check whether the device restarted; if not, treat as replay -> Contain |
| `seq_gap` | Injected message with a made-up seq, or dropped packets | Compare with broker connection log; one-off gap with packet loss is benign |
| `out_of_range` | Sensor fault or forged values | Check the physical sensor; if healthy, treat as spoofing |
| `zscore` | Subtle spoofing, real process change, or sensor drift | Cross-check neighbouring sensors and a manual reading |
| `malformed` | Wrong schema / fuzzing / firmware bug | Identify the publishing client in broker logs |

Escalate to **Contain** when two or more alert types hit the same device within 60 s, or any alert
appears on a device with a healthy physical reading.

## 1. Detect and confirm
1. Note first/last alert time, device ids, and alert types.
2. Pull broker logs for the window; look for unknown client ids, TLS failures
   (`certificate verify failed`, `peer did not return a certificate`) and repeated connects.
3. Verify the physical state (pH/EC/flow) by hand before trusting or dismissing the data.

## 2. Contain
- Spoofing via **stolen device cert**: revoke the cert (add to CRL, set `crl_file`, reload broker),
  or temporarily remove the ACL entry for that CN. The device stops publishing; mark its data untrusted.
- Rogue client on a non-mTLS listener: close listeners 1883/8884; only 8883 should be exposed.
- Switch downstream automation (dosing, pumps) to manual or safe defaults while telemetry is untrusted.

## 3. Eradicate
1. Re-issue certs with `certs/gen_certs.sh` (lab) or your CA (production) for affected devices.
2. Rotate the broker key if broker compromise is possible; rebuild the CA if the CA key was exposed.
3. Reflash/re-provision any device whose key may have been extracted.

## 4. Recover
- Restart detector (state is in-memory, so baselines rebuild from ~15 clean samples per sensor).
- Re-admit devices one at a time and watch for fresh alerts for 15 minutes.
- Backfill or discard telemetry from the untrusted window; do not use it to train baselines.

## 5. Post-incident
Record timeline, root cause, detection gap, and fix. Update `docs/SECURITY_REPORT.md` and add a detector
test in `tests/test_detector.py` for any miss.

## Quick checks

```bash
grep -c . results/mtls.alerts.jsonl                     # alert volume
jq -r '.alerts|join(",")' results/mtls.alerts.jsonl | sort | uniq -c   # by type
```
