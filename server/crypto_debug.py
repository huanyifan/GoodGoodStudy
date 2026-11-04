"""Local diagnostic bridge: public handshake in, synthetic encrypted config out.
Uses the actual service encryption function; never reads real profiles/configs.
stdout is protocol JSON, stderr contains explicitly allowlisted public trace data.
"""
import json
import sys
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
    emit("00.local_debug_scope", data="synthetic configuration only", transport="local stdin/stdout pipes",
        authentication="not exercised by this local crypto bridge; tested separately using the real HTTPS API")
    response = make_response(request, configuration, trace=emit)
    print(json.dumps(response, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Local crypto bridge failed; no sensitive context emitted.", file=sys.stderr)
        raise SystemExit(1) from None
