# Security Improvement Report: IoT telemetry pipeline

Scope: simulated sensor fleet -> Mosquitto 2.x -> detector, localhost lab. Results are from
`run_demo.py` (267 legitimate messages per scenario, 0 false positives in all three).

## Findings

| # | Finding | Severity | Evidence |
|---|---------|----------|----------|
| 1 | Plaintext, anonymous broker lets anyone publish as any device and read all telemetry | High | plain: 20/20 replayed and 20/20 forged messages delivered |
| 2 | TLS alone does not stop rogue clients; it only hides traffic from network sniffers | High | tls: identical delivery to plain; attacker connected anonymously |
| 3 | Without app-layer checks, delivered forgeries would be consumed as real data | High | detector is what flags them (see below) |
| 4 | A stolen device cert can still forge that device's own data | Medium | mtls: 10/10 forged messages from stolen `pump-01` cert delivered |

## Attack results

| Attack | plain | tls | mtls |
|--------|-------|-----|------|
| Replay (20 msgs) | delivered | delivered | blocked at handshake |
| Spoof, blatant values | delivered | delivered | blocked at handshake |
| Spoof, subtle values | delivered | delivered | blocked at handshake |
| Cert from rogue CA | n/a | n/a | rejected (verify failed) |
| Stolen pump-01 cert, own topic | n/a | n/a | delivered (detector flagged 10/10) |
| Stolen pump-01 cert, pump-02 topic | n/a | n/a | dropped by ACL (0 delivered) |

Detector: every delivered attack message was flagged (replay 20/20, blatant 10/10, subtle 10/10,
stolen-cert 10/10), 0/267 legitimate messages flagged.

## Fixes applied

1. **mTLS** on 8883: `require_certificate`, `use_identity_as_username`, anonymous disabled.
2. **Topic ACL**: `pattern write farm/%u/telemetry` pins each device to its own topic, so one
   compromised device cannot impersonate another. Devices have no read permission.
3. **Application-layer replay/anomaly detection**: monotonic `seq`, timestamp window (5 s),
   physical range limits, rolling z-score (|z|>5 over 40 samples). Flagged data is excluded from
   state, so an attacker cannot desync sequence tracking or poison baselines.

## Residual risk and next steps

- **Device cert theft** is the main remaining path. Mitigate with per-device cert expiry,
  revocation (CRL via `crl_file`), and secure-element or TPM key storage on real hardware.
- The detector is statistical and tuned to this simulator. A slow drift attack (a few sigma
  over hours) would evade a 40-sample window; add a long-horizon baseline and cross-sensor checks.
- Sequence numbers reset if a device reboots; real firmware needs a persistent counter or
  boot-epoch field so legitimate restarts don't alert.
- Clock skew limit assumes NTP-synced devices.
- Publishing is QoS 0, so ACL denials are silent to the publisher; monitor broker logs for denials.
- Not covered: payload signing, DoS/flooding, firmware tampering, broker-side rate limits.
