"""Loopback-only HTTPS fault fixture with synthetic credentials and TLS CA.
Used only by explicitly requested Rust integration tests, never deployed.
"""
import base64
import datetime
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
from config_server import make_response


def main():
    mode = sys.argv[1]
    profile = json.loads(sys.stdin.readline())
    requests = []
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GoodGoodStudy synthetic test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(ca_key, hashes.SHA256()))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, value):
            body = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/stats":
                self.reply(200, {"requests": requests})
            elif self.path == "/shutdown":
                self.reply(200, {})
                threading.Thread(target=self.server.shutdown, daemon=True).start()

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append({"clientPublicKey": body["clientPublicKey"], "clientNonce": body["clientNonce"]})
            if self.headers.get("Authorization") != "Bearer " + profile["accessToken"]:
                self.reply(401, {})
                return
            if mode in ("401", "403", "429", "500"):
                self.reply(int(mode), {})
                return
            if mode == "always_503" or (mode in ("502", "503", "504") and len(requests) == 1):
                self.reply(503 if mode == "always_503" else int(mode), {})
                return
            if mode == "drop" and len(requests) == 1:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            if mode == "timeout" and len(requests) == 1:
                time.sleep(0.5)
            response = make_response(body, {"intervalSeconds": 42, "mail": {"enabled": False}})
            if mode == "bad_mac":
                tag = bytearray(base64.b64decode(response["payload"]["mac"]))
                tag[0] ^= 1
                response["payload"]["mac"] = base64.b64encode(tag).decode()
            if mode == "invalid_json":
                self.send_response(200)
                self.send_header("Content-Length", "4")
                self.end_headers()
                self.wfile.write(b"nope")
            elif mode == "read_drop" and len(requests) == 1:
                self.send_response(200)
                self.send_header("Content-Length", "1000")
                self.end_headers()
                self.wfile.write(b'{"version":')
                self.wfile.flush()
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            else:
                self.reply(200, response)

    with tempfile.TemporaryDirectory(prefix="ggs-synthetic-tls-") as temporary:
        directory = Path(temporary)
        cert_path, key_path = directory / "leaf.pem", directory / "leaf.key"
        cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            server.socket = context.wrap_socket(server.socket, server_side=True)
            print(json.dumps({"url": "https://127.0.0.1:" + str(server.server_port),
                "ca": ca.public_bytes(serialization.Encoding.PEM).decode()}), flush=True)
            server.serve_forever(poll_interval=0.05)


if __name__ == "__main__":
    main()
