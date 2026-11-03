"""Authenticated, per-request ephemeral ECDH configuration service.
Only public points/nonces and ciphertext cross the wire. Session secrets are never
serialized. Persistent data contains configuration and credential hashes only.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL = "GoodGoodStudy.Config.ECDH-P256.HKDF-SHA256.v2"
ALGORITHM = "AES-256-CBC+HMAC-SHA256"
ENDPOINT = "/tools/goodgoodstudy/config.json"
MAX_REQUEST = 4096
MAX_CONFIG = 65536

def b64(value):
    return base64.b64encode(value).decode("ascii")

def unb64(value, length):
    if not isinstance(value, str):
        raise ValueError("base64 string required")
    result = base64.b64decode(value, validate=True)
    if len(result) != length:
        raise ValueError("invalid field length")
    return result

def make_response(request, configuration):
    if request.get("version") != 2:
        raise ValueError("unsupported version")
    device = request["deviceId"]
    client_nonce = unb64(request["clientNonce"], 32)
    client_public = unb64(request["clientPublicKey"], 65)
    if client_public[0] != 4:
        raise ValueError("uncompressed P-256 point required")
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public)
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    server_public = ephemeral.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    server_nonce = os.urandom(32)
    # Windows CNG's SHA256 KDF hashes the raw ECDH agreement before HKDF.
    hashed_secret = bytearray(hashlib.sha256(ephemeral.exchange(ec.ECDH(), peer)).digest())
    info = (PROTOCOL + "|" + device + "|").encode("utf-8") + client_public + server_public + client_nonce + server_nonce
    session_key = bytearray(HKDF(algorithm=hashes.SHA256(), length=64,
        salt=client_nonce + server_nonce, info=info).derive(bytes(hashed_secret)))
    try:
        plain = json.dumps(configuration, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(plain) > MAX_CONFIG:
            raise ValueError("configuration too large")
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plain) + padder.finalize()
        encryptor = Cipher(algorithms.AES(bytes(session_key[:32])), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        prefix = ("GoodGoodStudy.Config.v1|" + ALGORITHM + "|").encode("ascii")
        tag = hmac.new(bytes(session_key[32:]), prefix + iv + ciphertext, hashlib.sha256).digest()
        return {"version": 2, "keyAgreement": PROTOCOL, "serverPublicKey": b64(server_public),
            "serverNonce": b64(server_nonce), "payload": {"version": 1, "algorithm": ALGORITHM,
            "iv": b64(iv), "ciphertext": b64(ciphertext), "mac": b64(tag)}}
    finally:
        hashed_secret[:] = b"\0" * len(hashed_secret)
        session_key[:] = b"\0" * len(session_key)

class ConfigService:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.rate = defaultdict(deque)
        self.lock = threading.Lock()

    def authorized(self, device, header):
        if not isinstance(device, str) or len(device) != 36 or not header.startswith("Bearer "):
            return False
        token = header[7:]
        try:
            unb64(token, 32)
            devices = json.loads((self.data_dir / "devices.json").read_text("utf-8"))
            expected = devices.get(device, "")
            actual = hashlib.sha256(token.encode("ascii")).hexdigest()
            return len(expected) == 64 and hmac.compare_digest(actual, expected)
        except (ValueError, OSError, UnicodeError):
            return False

    def allow(self, device):
        now = time.monotonic()
        with self.lock:
            recent = self.rate[device]
            while recent and recent[0] < now - 60:
                recent.popleft()
            if len(recent) >= 60:
                return False
            recent.append(now)
            return True

    def configuration(self):
        path = self.data_dir / "config.json"
        if path.stat().st_size > MAX_CONFIG:
            raise ValueError("configuration too large")
        result = json.loads(path.read_text("utf-8-sig"))
        if not isinstance(result, dict):
            raise ValueError("configuration must be an object")
        return result

def handler_for(service):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ConfigService"
        sys_version = ""
        def log_message(self, fmt, *args):
            # Do not log headers, profile tokens, request/response bodies or keys.
            return
        def setup(self):
            super().setup()
            self.connection.settimeout(10)
        def reply(self, status, value):
            body = json.dumps(value, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Vary", "Authorization")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            self.reply(401 if self.path == ENDPOINT else 404, {"error": "unauthorized"})
        def do_POST(self):
            if self.path != ENDPOINT:
                self.reply(404, {"error": "not_found"})
                return
            try:
                if self.headers.get("Transfer-Encoding"):
                    raise ValueError("unsupported transfer encoding")
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > MAX_REQUEST:
                    raise ValueError("invalid body size")
                body = self.rfile.read(length)
                if not self.headers.get("Authorization", "").startswith("Bearer "):
                    self.reply(401, {"error": "unauthorized"})
                    return
                request = json.loads(body.decode("utf-8"))
                if not isinstance(request, dict):
                    raise ValueError("invalid body")
                device = request.get("deviceId")
                if not service.authorized(device, self.headers.get("Authorization", "")):
                    self.reply(401, {"error": "unauthorized"})
                    return
                if not service.allow(device):
                    self.reply(429, {"error": "rate_limited"})
                    return
                result = make_response(request, service.configuration())
            except (ValueError, KeyError, TypeError, UnicodeError):
                self.reply(400, {"error": "invalid_request"})
                return
            except Exception:
                self.reply(503, {"error": "unavailable"})
                return
            self.reply(200, result)
    return Handler

class BoundedServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)
    def process_request(self, request, address):
        if not self.slots.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise
    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        # Failed sockets must not dump request context into container logs.
        return

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8093)
    parser.add_argument("--data-dir", required=True)
    args = parser.parse_args()
    service = ConfigService(args.data_dir)
    service.configuration()
    json.loads((service.data_dir / "devices.json").read_text("utf-8"))
    with BoundedServer((args.bind, args.port), handler_for(service)) as server:
        server.serve_forever()

if __name__ == "__main__":
    main()
