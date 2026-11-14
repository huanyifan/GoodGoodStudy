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
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

PROTOCOL = "GoodGoodStudy.Config.ECDH-P256.HKDF-SHA256.v2"
PROTOCOL_V3 = "GoodGoodStudy.Config.ECDH-P256.HKDF-SHA256.v3"
ALGORITHM = "AES-256-CBC+HMAC-SHA256"
ENDPOINT = "/tools/goodgoodstudy/config.json"
MAX_REQUEST = 4096
MAX_CONFIG = 65536
# v3 authenticates both directions with ECDSA P-256 over domain-separated transcripts.
REQUEST_DOMAIN = b"GoodGoodStudy.Config.Request.v3"
RESPONSE_DOMAIN = b"GoodGoodStudy.Config.Response.v3"
MAX_CLOCK_SKEW = 300
NONCE_TTL = 300
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class AuthError(Exception):
    """Well-formed request that failed authentication (maps to HTTP 401)."""


def sign_raw(private_key, message):
    # Fixed 64-byte r||s, low-S normalised so strict verifiers (RustCrypto) accept it.
    r, s = decode_dss_signature(private_key.sign(message, ec.ECDSA(hashes.SHA256())))
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_raw(public_key, signature, message):
    if len(signature) != 64:
        raise InvalidSignature("signature length")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < P256_ORDER and 1 <= s < P256_ORDER):
        raise InvalidSignature("signature range")
    public_key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))


def request_transcript(device, client_public, client_nonce, timestamp):
    return (REQUEST_DOMAIN + b"|" + device.encode("utf-8") + b"|"
            + client_public + client_nonce + timestamp.to_bytes(8, "big"))


def response_transcript(device, server_public, client_public, server_nonce, client_nonce, timestamp):
    return (RESPONSE_DOMAIN + b"|" + device.encode("utf-8") + b"|"
            + server_public + client_public + server_nonce + client_nonce + timestamp.to_bytes(8, "big"))


def valid_timestamp(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**63


def load_signing_key(data_dir):
    raw = json.loads((Path(data_dir) / "signing-key.json").read_text("utf-8"))
    scalar = base64.b64decode(raw["privateKey"], validate=True)
    if len(scalar) != 32:
        raise ValueError("invalid signing key")
    return ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())

def b64(value):
    return base64.b64encode(value).decode("ascii")

def unb64(value, length):
    if not isinstance(value, str):
        raise ValueError("base64 string required")
    result = base64.b64decode(value, validate=True)
    if len(result) != length:
        raise ValueError("invalid field length")
    return result

def make_response(request, configuration, signing_key=None, trace=None):
    version = request.get("version")
    if version not in (2, 3):
        raise ValueError("unsupported version")
    device = request["deviceId"]
    client_nonce = unb64(request["clientNonce"], 32)
    client_public = unb64(request["clientPublicKey"], 65)
    if client_public[0] != 4:
        raise ValueError("uncompressed P-256 point required")
    protocol = PROTOCOL_V3 if version == 3 else PROTOCOL
    timestamp = None
    if version == 3:
        timestamp = request["timestamp"]
        if not valid_timestamp(timestamp):
            raise ValueError("invalid timestamp")
        if signing_key is None:
            raise ValueError("server signing key unavailable")
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public)
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    server_public = ephemeral.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    server_nonce = os.urandom(32)
    if trace:
        trace("01.validate_client_and_generate_ephemeral", curve="P-256 / secp256r1",
            clientPublicKey=b64(client_public), clientNonce=b64(client_nonce),
            serverPublicKey=b64(server_public), serverNonce=b64(server_nonce),
            pointOnCurve=True, privateKey="[memory only; redacted]")
    # Windows CNG's SHA256 KDF hashes the raw ECDH agreement before HKDF.
    hashed_secret = bytearray(hashlib.sha256(ephemeral.exchange(ec.ECDH(), peer)).digest())
    info = (protocol + "|" + device + "|").encode("utf-8") + client_public + server_public + client_nonce + server_nonce
    if version == 3:
        # Bind the derived key to the signed timestamp so a key cannot outlive its transcript.
        info += timestamp.to_bytes(8, "big")
    session_key = bytearray(HKDF(algorithm=hashes.SHA256(), length=64,
        salt=client_nonce + server_nonce, info=info).derive(bytes(hashed_secret)))
    try:
        if trace:
            trace("02.ecdh_sha256_hkdf", calculation="Z = ECDH(server_private, client_public); IKM = SHA256(Z)",
                saltLayout="client_nonce[32] || server_nonce[32]", saltBase64=b64(client_nonce + server_nonce),
                infoLayout="UTF8(protocol + '|' + device_id + '|') || client_public[65] || server_public[65] || client_nonce[32] || server_nonce[32]",
                infoBytes=len(info), infoSha256=hashlib.sha256(info).hexdigest(),
                outputBytes=64, split="OKM[0..32] AES-256 key; OKM[32..64] HMAC-SHA256 key",
                sharedSecretAndDerivedKeys="[memory only; redacted]")
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
        if trace:
            trace("03.aes_encrypt_and_authenticate", cipher="AES-256-CBC", padding="PKCS#7, 16-byte blocks",
                plaintextBytes=len(plain), plaintextConfiguration="[redacted]", paddedBytes=len(padded),
                ivBase64=b64(iv), ivBytes=len(iv), ciphertextBytes=len(ciphertext),
                ciphertextSha256=hashlib.sha256(ciphertext).hexdigest(), macBase64=b64(tag),
                macInputLayout="ASCII('GoodGoodStudy.Config.v1|" + ALGORITHM + "|') || IV[16] || ciphertext",
                macBytes=len(tag), order="encrypt then MAC; client must verify MAC before decryption")
        response = {"version": version, "keyAgreement": protocol, "serverPublicKey": b64(server_public),
            "serverNonce": b64(server_nonce), "payload": {"version": 1, "algorithm": ALGORITHM,
            "iv": b64(iv), "ciphertext": b64(ciphertext), "mac": b64(tag)}}
        if version == 3:
            response["timestamp"] = timestamp
            transcript = response_transcript(device, server_public, client_public, server_nonce, client_nonce, timestamp)
            response["signature"] = b64(sign_raw(signing_key, transcript))
            if trace:
                trace("03b.sign_response", domain=RESPONSE_DOMAIN.decode("ascii"),
                    transcriptLayout="domain || '|' || device || '|' || server_public[65] || client_public[65] || server_nonce[32] || client_nonce[32] || timestamp[8]",
                    signatureEncoding="ECDSA P-256 / SHA-256, raw r||s, 64 bytes, low-S", signatureBase64=response["signature"])
        return response
    finally:
        hashed_secret[:] = b"\0" * len(hashed_secret)
        session_key[:] = b"\0" * len(session_key)
        if trace:
            trace("04.cleanup", zeroedBuffers=["hashed_secret", "session_key"], keyPersistence=False,
                limitation="Python/OpenSSL temporary copies are runtime-managed; zeroing these buffers is not a guarantee of erasing every copy")

class ConfigService:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.rate = defaultdict(deque)
        self.rate_ip = defaultdict(deque)
        self.nonces = {}
        self.lock = threading.Lock()
        try:
            self.signing_key = load_signing_key(self.data_dir)
        except (OSError, ValueError, KeyError):
            # v2-only deployments run without a signing key; v3 requests then get 401.
            self.signing_key = None

    def devices(self):
        return json.loads((self.data_dir / "devices.json").read_text("utf-8"))

    def authorized(self, device, header):
        if not isinstance(device, str) or len(device) != 36 or not header.startswith("Bearer "):
            return False
        token = header[7:]
        try:
            unb64(token, 32)
            expected = self.devices().get(device, "")
            actual = hashlib.sha256(token.encode("ascii")).hexdigest()
            # v3 entries are objects, not hex strings, so they never satisfy the v2 path.
            return isinstance(expected, str) and len(expected) == 64 and hmac.compare_digest(actual, expected)
        except (ValueError, OSError, UnicodeError):
            return False

    def device_public_key(self, device):
        if not isinstance(device, str) or len(device) != 36:
            return None
        try:
            entry = self.devices().get(device)
        except (ValueError, OSError, UnicodeError):
            return None
        if not isinstance(entry, dict):
            return None
        try:
            raw = base64.b64decode(entry.get("publicKey", ""), validate=True)
            if len(raw) != 65 or raw[0] != 4:
                return None
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        except (ValueError, TypeError):
            return None

    def _allow(self, bucket, key, limit):
        now = time.monotonic()
        with self.lock:
            recent = bucket[key]
            while recent and recent[0] < now - 60:
                recent.popleft()
            if len(recent) >= limit:
                return False
            recent.append(now)
            return True

    def allow(self, device):
        return self._allow(self.rate, device, 60)

    def allow_ip(self, ip):
        return self._allow(self.rate_ip, ip, 120)

    def fresh_nonce(self, nonce_b64):
        now = time.monotonic()
        with self.lock:
            if len(self.nonces) > 200000:
                self.nonces.clear()
            for key in [k for k, expiry in self.nonces.items() if expiry < now]:
                del self.nonces[key]
            if nonce_b64 in self.nonces:
                return False
            self.nonces[nonce_b64] = now + NONCE_TTL
            return True

    def authenticate_v3(self, request):
        # Raises AuthError (401) on auth failure, ValueError (400) on malformed input.
        if self.signing_key is None:
            raise AuthError("v3 unavailable")
        device = request.get("deviceId")
        public_key = self.device_public_key(device)
        if public_key is None:
            raise AuthError("unknown device")
        client_public = unb64(request["clientPublicKey"], 65)
        client_nonce = unb64(request["clientNonce"], 32)
        if client_public[0] != 4:
            raise ValueError("uncompressed P-256 point required")
        timestamp = request["timestamp"]
        if not valid_timestamp(timestamp):
            raise ValueError("invalid timestamp")
        if abs(timestamp - int(time.time())) > MAX_CLOCK_SKEW:
            raise AuthError("stale timestamp")
        signature = base64.b64decode(request["signature"], validate=True)
        try:
            verify_raw(public_key, signature, request_transcript(device, client_public, client_nonce, timestamp))
        except InvalidSignature:
            raise AuthError("bad signature")
        if not self.fresh_nonce(request["clientNonce"]):
            raise AuthError("replayed nonce")
        return device

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
                # Per-IP limit is applied before any authentication work.
                if not service.allow_ip(self.client_address[0]):
                    self.reply(429, {"error": "rate_limited"})
                    return
                request = json.loads(body.decode("utf-8"))
                if not isinstance(request, dict):
                    raise ValueError("invalid body")
                version = request.get("version")
                try:
                    if version == 2:
                        device = request.get("deviceId")
                        if not service.authorized(device, self.headers.get("Authorization", "")):
                            raise AuthError("unauthorized")
                        signing_key = None
                    elif version == 3:
                        device = service.authenticate_v3(request)
                        signing_key = service.signing_key
                    else:
                        raise ValueError("unsupported version")
                except AuthError:
                    self.reply(401, {"error": "unauthorized"})
                    return
                if not service.allow(device):
                    self.reply(429, {"error": "rate_limited"})
                    return
                result = make_response(request, service.configuration(), signing_key=signing_key)
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
