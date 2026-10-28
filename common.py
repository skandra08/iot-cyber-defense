"""Shared helpers: MQTT client factory for the three transport modes."""
import json
import ssl
import threading
from pathlib import Path

import paho.mqtt.client as mqtt

ROOT = Path(__file__).parent
CERTS = ROOT / "certs"
HOST = "127.0.0.1"
PORTS = {"plain": 1883, "tls": 8884, "mtls": 8883}
TELEMETRY_TOPIC = "farm/{device}/telemetry"
DEVICES = ["pump-01", "pump-02", "pump-03"]


def make_client(mode, client_id, cert_as=None):
    """Build a client. mode: plain | tls (server auth only) | mtls (client cert).

    cert_as names a cert in certs/ (e.g. 'pump-01'); in mtls mode, omitting it
    means the client presents no certificate.
    """
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    if mode in ("tls", "mtls"):
        kwargs = {"ca_certs": str(CERTS / "ca.crt"), "tls_version": ssl.PROTOCOL_TLS_CLIENT}
        if mode == "mtls" and cert_as:
            kwargs["certfile"] = str(CERTS / f"{cert_as}.crt")
            kwargs["keyfile"] = str(CERTS / f"{cert_as}.key")
        client.tls_set(**kwargs)
    return client


def connect(client, mode, timeout=3.0):
    """Connect and wait for CONNACK. Returns (ok, reason)."""
    done = threading.Event()
    result = {}

    def on_connect(c, userdata, flags, reason_code, properties):
        result["rc"] = reason_code
        done.set()

    client.on_connect = on_connect
    try:
        client.connect(HOST, PORTS[mode], keepalive=30)
    except (OSError, ssl.SSLError) as exc:
        return False, f"connect failed: {exc}"
    client.loop_start()
    if not done.wait(timeout):
        client.loop_stop()
        return False, "no CONNACK (TLS handshake rejected or timed out)"
    if result["rc"].is_failure:
        client.loop_stop()
        return False, f"broker refused: {result['rc']}"
    return True, "connected"


def dumps(msg):
    return json.dumps(msg, separators=(",", ":"))
