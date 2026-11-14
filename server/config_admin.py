"""Enroll a device and generate the server signing key.

v2 devices are stored as a token hash; v3 devices are stored as their public key.
Raw tokens and private keys are never retained in the device registry.
"""
import argparse
import base64
import hashlib
import json
import os
import uuid
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _atomic_write(path, text, mode=0o600):
    path = Path(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        fd = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(str(temporary), str(path))
    finally:
        if temporary.exists():
            temporary.unlink()


def _device_public_key(scalar_b64):
    scalar = base64.b64decode(scalar_b64, validate=True)
    if len(scalar) != 32:
        raise ValueError("invalid device key")
    private = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return base64.b64encode(public).decode("ascii")


def enroll(profile_path, devices_path):
    profile_path, devices_path = Path(profile_path), Path(devices_path)
    if profile_path.stat().st_size > 4096:
        raise ValueError("profile too large")
    profile = json.loads(profile_path.read_text("utf-8-sig"))
    device = profile["deviceId"]
    uuid.UUID(device)
    devices = json.loads(devices_path.read_text("utf-8")) if devices_path.exists() else {}
    if "deviceKey" in profile:
        devices[device] = {"publicKey": _device_public_key(profile["deviceKey"])}
        kind = "v3 public key"
    else:
        token = profile["accessToken"]
        if len(base64.b64decode(token, validate=True)) != 32:
            raise ValueError("invalid token")
        devices[device] = hashlib.sha256(token.encode("ascii")).hexdigest()
        kind = "v2 token hash"
    _atomic_write(devices_path, json.dumps(devices, separators=(",", ":")))
    return kind


def keygen_signing_key(path):
    path = Path(path)
    if path.exists():
        raise ValueError("signing key already exists; refusing to overwrite")
    private = ec.generate_private_key(ec.SECP256R1())
    scalar = private.private_numbers().private_value.to_bytes(32, "big")
    public = private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    _atomic_write(path, json.dumps({"privateKey": base64.b64encode(scalar).decode("ascii")}))
    return base64.b64encode(public).decode("ascii")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile")
    parser.add_argument("--devices")
    parser.add_argument("--keygen-signing-key", metavar="PATH",
                        help="generate the server ECDSA signing key and print its public key")
    args = parser.parse_args()
    if args.keygen_signing_key:
        public = keygen_signing_key(args.keygen_signing_key)
        print("Server signing key created; embed this public key in the clients:")
        print(public)
    elif args.profile and args.devices:
        kind = enroll(args.profile, args.devices)
        print("Device enrolled; stored " + kind + " only.")
    else:
        parser.error("provide --profile and --devices, or --keygen-signing-key")
