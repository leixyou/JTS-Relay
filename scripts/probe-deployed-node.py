#!/usr/bin/env python3
"""Bounded operator smoke for an explicitly authorized node, not endpoint acceptance.

Optional operator dependencies: cryptography 46.0.7, websockets 13.1.
Supply two disposable P-256 PEM keys; --admission emits only their public records.
Private keys/tickets/payloads are never printed. TLS verifies a caller-pinned test
certificate and the URL host; no OS trust changes, proxy or redirect fallback.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import sys
import traceback
import urllib.error
import urllib.parse
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from websockets.sync.client import connect


def require(condition):
    if not condition:
        raise ValueError("probe_assertion_failed")


class Identity:
    def __init__(self, path):
        self.key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        require(isinstance(self.key, ec.EllipticCurvePrivateKey) and isinstance(self.key.curve, ec.SECP256R1))
        self.spki = self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.id = hashlib.sha256(self.spki).hexdigest()

    def admission(self, role, peer):
        return dict(deviceId=self.id, publicKeySpkiBase64=base64.b64encode(self.spki).decode(), role=role, peers=[peer.id])

    def envelope(self, operation, challenge, payload, origin):
        data = json.dumps(payload, separators=(",", ":")).encode()
        canonical = "\n".join(("JTS-RELAY-AUTH-V2", origin, self.id, operation, challenge["challengeId"],
                               challenge["nonceBase64"], hashlib.sha256(data).hexdigest())).encode()
        r, s = utils.decode_dss_signature(self.key.sign(canonical, ec.ECDSA(hashes.SHA256())))
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return dict(deviceId=self.id, challengeId=challenge["challengeId"],
                    payloadBase64=base64.b64encode(data).decode(), signatureBase64=base64.b64encode(signature).decode())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Probe:
    def __init__(self, origin, certificate, expected_hash):
        uri = urllib.parse.urlsplit(origin)
        require(uri.scheme == "https" and uri.hostname and uri.path in ("", "/") and not uri.query
                and not uri.fragment and not uri.username and not uri.password)
        authority = ("[" + uri.hostname + "]") if ":" in uri.hostname else uri.hostname
        self.origin = "https://" + authority.lower() + (":" + str(uri.port) if uri.port and uri.port != 443 else "")
        self.host, self.port = uri.hostname, uri.port or 443
        self.socket_url = "wss://" + uri.netloc + "/v1/channel"
        pem = Path(certificate).read_bytes()
        require(x509.load_pem_x509_certificate(pem).fingerprint(hashes.SHA256()).hex() == expected_hash.lower())
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_2
        self.tls.load_verify_locations(cadata=pem.decode("ascii"))
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                     urllib.request.HTTPSHandler(context=self.tls), NoRedirect())

    def request(self, path, body=None):
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(self.origin + path, data, {"Content-Type": "application/json"})
        with self.http.open(request, timeout=8) as response:
            content = response.read(32769)
            require(len(content) <= 32768)
            return json.loads(content)

    def authorized(self, identity, operation, payload):
        challenge = self.request("/v1/challenges", dict(deviceId=identity.id, operation=operation))
        return self.request("/v1/" + operation, identity.envelope(operation, challenge, payload, self.origin))

    def socket(self, ticket):
        return connect(self.socket_url, ssl=self.tls, additional_headers={"Authorization": "Bearer " + ticket},
                       compression=None, open_timeout=8, close_timeout=2, max_size=32768)

    def reject_replay(self, ticket):
        # websockets 13.1 cannot decode chunked HTTP rejection bodies. Verify the
        # actual rejection with the HTTP stack, not by accepting a parser error.
        # urllib forces Connection: close; use http.client to preserve Upgrade.
        connection = http.client.HTTPSConnection(self.host, self.port, context=self.tls, timeout=8)
        try:
            connection.request("GET", "/v1/channel", headers={
                "Authorization": "Bearer " + ticket, "Connection": "Upgrade", "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode()})
            response = connection.getresponse()
            require(response.status == 401 and json.loads(response.read(1025)) == {"code": "invalid_ticket"})
        finally:
            connection.close()

    def lane(self, controller, companion, lane):
        session = self.authorized(controller, "sessions", dict(peerDeviceId=companion.id, lane=lane))
        require(session["channelPath"] == "/v1/channel")
        offers = self.authorized(companion, "poll", {})["offers"]
        offer = next(item for item in offers if item["sessionId"] == session["sessionId"])
        require(offer["lane"] == lane and offer["controllerDeviceId"] == controller.id)
        with self.socket(session["ticket"]) as left, self.socket(offer["ticket"]) as right:
            for peer in (left, right):
                ready = json.loads(peer.recv(timeout=8))
                require(ready == dict(ready=True, sessionId=session["sessionId"], lane=lane))
            self.reject_replay(session["ticket"])
            for source, target in ((left, right), (right, left)):
                payload = os.urandom(8192)  # Synthetic opaque bytes, never a real script, file or desktop.
                source.send(payload)
                received = bytearray()
                while len(received) < len(payload):
                    part = target.recv(timeout=8)
                    require(isinstance(part, bytes) and len(part) > 0)
                    received.extend(part)
                    require(len(received) <= len(payload))
                require(received == payload)
        return dict(lane=lane, bidirectionalBytes=16384, ticketReplayRejected=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-key", required=True)
    parser.add_argument("--companion-key", required=True)
    parser.add_argument("--admission", action="store_true")
    parser.add_argument("--origin")
    parser.add_argument("--certificate")
    parser.add_argument("--certificate-sha256")
    args = parser.parse_args()
    controller, companion = Identity(args.controller_key), Identity(args.companion_key)
    require(controller.id != companion.id)
    if args.admission:
        print(json.dumps([controller.admission("controller", companion), companion.admission("companion", controller)]))
        return
    require(args.origin and args.certificate and args.certificate_sha256)
    probe = Probe(args.origin, args.certificate, args.certificate_sha256)
    require(probe.request("/healthz") == {"status": "ok"})
    require(probe.request("/v1/info") == {"protocolVersion": 1, "lanes": ["control", "file", "rdp"]})
    try:
        probe.request("/v1/challenges", {"deviceId": "f" * 64, "operation": "presence"})
        raise ValueError("unknown_identity_accepted")
    except urllib.error.HTTPError as error:
        require(error.code == 401)
    require(probe.authorized(companion, "presence", {}) == {"deviceId": companion.id})
    peers = probe.authorized(controller, "devices", {})["devices"]
    require(len(peers) == 1 and peers[0]["deviceId"] == companion.id and isinstance(peers[0]["lastSeenAtUnixSeconds"], int))
    lanes = [probe.lane(controller, companion, lane) for lane in ("control", "file", "rdp")]
    print(json.dumps(dict(ok=True, tlsCertificateAndHostVerified=True, unknownIdentityRejected=True,
                         signedPresenceAndPeerScope=True, lanes=lanes, endpointAcceptance=False)))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("node_probe_failed:" + type(error).__name__, file=sys.stderr)
        # Stack locations only: never dump an exception message, URL, headers or locals.
        for frame in traceback.extract_tb(error.__traceback__)[-5:]:
            print(f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}", file=sys.stderr)
        sys.exit(1)
