"""Local diagnostic bridge: public handshake in, synthetic encrypted config out.
Uses the actual service encryption function; never reads real profiles/configs.
stdout is protocol JSON, stderr contains explicitly allowlisted public trace data.
"""
import base64
import json
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from config_server import make_response


def emit(step, **details):
    print(json.dumps({"side": "server", "step": step, "details": details},
        ensure_ascii=True, separators=(",", ":")), file=sys.stderr, flush=True)


def main():
    body = sys.stdin.buffer.read(4097)
    if len(body) > 4096:
        raise ValueError("handshake too large")
    request = json.loads(body)
    configuration = {"intervalSeconds": 42, "batchSize": 3, "mail": {"enabled": False}}
    # Per-run signing key; its public half travels in the response so the local
    # client can verify the v3 server signature without a shared enrolment step.
    signing_key = ec.generate_private_key(ec.SECP256R1())
    signing_public = base64.b64encode(signing_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode("ascii")
    emit("00.local_debug_scope", data="synthetic configuration only", transport="local stdin/stdout pipes",
        authentication="device signature not verified by this local bridge; tested separately using the real HTTPS API",
        serverSigningKey=signing_public)
    response = make_response(request, configuration, signing_key=signing_key, trace=emit)
    response["serverSigningKey"] = signing_public
    print(json.dumps(response, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Local crypto bridge failed; no sensitive context emitted.", file=sys.stderr)
        raise SystemExit(1) from None
