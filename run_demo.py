"""Run the full build-attack-defend lab against a local Mosquitto broker.

For each transport mode (plain, tls, mtls) it starts sensors + detector, fires
the attacks, and scores what reached the detector and what it caught.
"""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
PY = sys.executable
MOSQUITTO = "/opt/homebrew/opt/mosquitto/sbin/mosquitto"
RUN = 20  # seconds per mode


def sh(*args, bg=False):
    cmd = [str(a) for a in args]
    return subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) if bg \
        else subprocess.run(cmd, cwd=ROOT, check=True)


def wait_port(port, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"broker not listening on {port}")


def atk(mode, script, *extra):
    return sh(PY, f"attacks/{script}.py", "--mode", mode, *extra, bg=True)


def scenario(mode):
    det = sh(PY, "detector.py", "--mode", mode, "--duration", RUN, "--out", f"results/{mode}.json", bg=True)
    time.sleep(0.5)
    sensors = sh(PY, "sensor.py", "--mode", mode, "--duration", RUN - 2, bg=True)
    time.sleep(1)
    attacks = [atk(mode, "replay", "--record", 3, "--delay", 4)]  # sniffs ~t1-4s, replays ~t8s
    time.sleep(4)
    attacks.append(atk(mode, "spoof", "--style", "blatant"))
    time.sleep(4)
    attacks.append(atk(mode, "spoof", "--style", "subtle"))
    if mode == "mtls":
        time.sleep(3)
        # attacker with a cert from a rogue CA, and with a *stolen* pump-01 cert
        attacks.append(atk(mode, "spoof", "--style", "blatant", "--cert-as", "rogue", "--tag", "_roguecert"))
        attacks.append(atk(mode, "spoof", "--style", "blatant", "--cert-as", "pump-01", "--target", "pump-01",
                           "--tag", "_stolen_own_topic"))
        attacks.append(atk(mode, "spoof", "--style", "blatant", "--cert-as", "pump-01", "--target", "pump-02",
                           "--tag", "_stolen_other_topic"))
    attack_out = []
    for a in attacks:
        out, _ = a.communicate()
        attack_out += [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    sensors.communicate()
    det.communicate()
    result = json.loads((ROOT / f"results/{mode}.json").read_text())
    result["attacks"] = attack_out
    return result


def summarize(all_results):
    lines = []
    for mode, res in all_results.items():
        seen, flagged = res["seen"], res["flagged"]
        legit, fp = seen.get("legit", 0), flagged.get("legit", 0)
        lines.append(f"\n== {mode.upper()} ==  legit msgs {legit}, false positives {fp}")
        lines.append(f"  {'attack':<34}{'connected':<11}{'sent':<6}{'delivered':<11}{'detected'}")
        for a in res["attacks"]:
            name = a["attack"]
            lines.append(f"  {name:<34}{str(a['connected']):<11}{a['sent']:<6}{seen.get(name, 0):<11}{flagged.get(name, 0)}")
            if not a["connected"]:
                lines.append(f"      -> {a['reason'][:90]}")
    return "\n".join(lines)


def main():
    (ROOT / "results").mkdir(exist_ok=True)
    sh("bash", "certs/gen_certs.sh")
    conf = (ROOT / "broker/mosquitto.conf.tmpl").read_text().replace("@ROOT@", str(ROOT))
    (ROOT / "broker/mosquitto.conf").write_text(conf)
    broker = subprocess.Popen([MOSQUITTO, "-c", str(ROOT / "broker/mosquitto.conf")],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    results = {}
    try:
        for port in (1883, 8884, 8883):
            wait_port(port)
        for mode in ("plain", "tls", "mtls"):
            print(f"running {mode} scenario ({RUN}s)...", flush=True)
            results[mode] = scenario(mode)
    finally:
        broker.terminate()
        broker_log = broker.communicate()[0]
    (ROOT / "results/summary.json").write_text(json.dumps(results, indent=2))
    text = summarize(results)
    (ROOT / "results/summary.txt").write_text(text + "\n")
    print(text)
    if broker_log.strip():
        print("\nbroker log:\n" + broker_log[-1500:])


if __name__ == "__main__":
    main()
