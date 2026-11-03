"""Enroll a device profile into private server metadata; never retain raw tokens."""
import argparse
import base64
import hashlib
import json
import os
import uuid
from pathlib import Path

def enroll(profile_path, devices_path):
    profile_path, devices_path = Path(profile_path), Path(devices_path)
    if profile_path.stat().st_size > 4096:
        raise ValueError("profile too large")
    profile = json.loads(profile_path.read_text("utf-8-sig"))
    device = profile["deviceId"]
    uuid.UUID(device)
    token = profile["accessToken"]
    if len(base64.b64decode(token, validate=True)) != 32:
        raise ValueError("invalid token")
    devices = json.loads(devices_path.read_text("utf-8")) if devices_path.exists() else {}
    devices[device] = hashlib.sha256(token.encode("ascii")).hexdigest()
    temporary = devices_path.with_name(devices_path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        fd = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(devices, stream, separators=(",", ":"))
        os.replace(str(temporary), str(devices_path))
    finally:
        if temporary.exists():
            temporary.unlink()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--devices", required=True)
    args = parser.parse_args()
    enroll(args.profile, args.devices)
    print("Device enrolled; only its token hash is retained.")
