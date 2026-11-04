"""Run native client traces, correlate both implementations, keep logs local."""
import argparse
import datetime
import json
from pathlib import Path
import subprocess


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def event(events, side, step):
    matches = [item for item in events if item.get("side") == side and item.get("step") == step]
    require(len(matches) == 1, "Missing or duplicate trace event: " + step)
    return matches[0]["details"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--offline-only", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = args.output_dir / ("crypto-debug-" + stamp + ".log")
    report = {"localRoundTrip": False, "tamperRejections": 0, "crossSessionReplayRejected": False,
        "liveHttpsRuns": 0, "freshSessionParameters": False, "screenshotsOrMailStarted": False}
    with path.open("x", encoding="utf-8") as log:
        def run(label, *arguments):
            log.write("\n=== " + label + " ===\n")
            log.flush()
            proc = subprocess.run([str(args.exe), *map(str, arguments)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=45, check=False)
            output = proc.stdout.decode("utf-8", errors="replace").replace("\r\r\n", "\n").replace("\r\n", "\n")
            log.write(output)
            log.flush()
            print(output, end="", flush=True)
            require(proc.returncode == 0, label + " failed; see sanitized trace log")
            return [json.loads(line) for line in output.splitlines() if line.startswith("{")]

        local = run("LOCAL Rust client + actual Python service encryption", "--debug-crypto", root / "server/crypto_debug.py")
        client = event(local, "client", "01.generate_ephemeral_handshake")
        server = event(local, "server", "01.validate_client_and_generate_ephemeral")
        received = event(local, "client", "04.validate_server_handshake")
        for name in ("clientPublicKey", "clientNonce"):
            require(client[name] == server[name], "Client handshake mismatch: " + name)
        for name in ("serverPublicKey", "serverNonce"):
            require(server[name] == received[name], "Server handshake mismatch: " + name)
        ck = event(local, "client", "06.hkdf_sha256")
        sk = event(local, "server", "02.ecdh_sha256_hkdf")
        for name in ("saltBase64", "infoBytes", "infoSha256", "outputBytes"):
            require(ck[name] == sk[name], "HKDF public inputs mismatch: " + name)
        ce = event(local, "client", "07.encrypted_envelope")
        se = event(local, "server", "03.aes_encrypt_and_authenticate")
        for name in ("ivBase64", "ivBytes", "ciphertextBytes", "ciphertextSha256", "macBase64", "macBytes"):
            require(ce[name] == se[name], "Encrypted envelope mismatch: " + name)
        require(event(local, "client", "08.hmac_verified")["valid"], "HMAC verification failed")
        report["localRoundTrip"] = True
        report["tamperRejections"] = sum(item.get("step") == "tamper_rejected" for item in local)
        report["crossSessionReplayRejected"] = any(item.get("step") == "cross_session_replay_rejected" for item in local)
        require(report["tamperRejections"] == 4 and report["crossSessionReplayRejected"], "Negative checks failed")
        if not args.offline_only:
            rounds = [run("LIVE HTTPS round " + str(i + 1), "--debug-config") for i in range(2)]
            for events in rounds:
                require(event(events, "client", "03.https_response")["status"] == 200, "HTTPS status failed")
                require(event(events, "client", "08.hmac_verified")["valid"], "Live HMAC check failed")
                event(events, "client", "09.aes_decrypt_and_validate")
                report["liveHttpsRuns"] += 1
            for step, names in (
                ("01.generate_ephemeral_handshake", ("clientPublicKey", "clientNonce")),
                ("04.validate_server_handshake", ("serverPublicKey", "serverNonce")),
                ("07.encrypted_envelope", ("ivBase64", "ciphertextSha256")),
            ):
                a, b = [event(events, "client", step) for events in rounds]
                for name in names:
                    require(a[name] != b[name], "Repeated session parameter: " + name)
            report["freshSessionParameters"] = True
        log.write("\nPASS " + json.dumps(report, ensure_ascii=True) + "\n")
    summary = path.with_suffix(".json")
    summary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("PASS", json.dumps(report))
    print("Trace log:", path)
    print("Summary:", summary)


if __name__ == "__main__":
    main()
