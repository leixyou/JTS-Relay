"""Public P-256 admission validation. No private-key or endpoint dependencies."""
import base64
import copy
import hashlib
import json


class AdmissionError(Exception):
    """Only fixed, non-sensitive codes are reported to the operator."""


def require(condition, code):
    if not condition:
        raise AdmissionError(code)


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_property")
        result[key] = value
    return result


def decode(raw):
    try:
        result = json.loads(raw, object_pairs_hook=_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(AdmissionError("invalid_json_number")))
        require(isinstance(result, dict), "json_object_required")
        return result
    except (ValueError, UnicodeError, RecursionError) as error:
        raise AdmissionError("invalid_json") from error


def field(obj, name, default=None):
    require(isinstance(obj, dict), "invalid_configuration_object")
    matches = [key for key in obj if key.casefold() == name.casefold()]
    require(len(matches) <= 1, "ambiguous_configuration_property")
    return obj[matches[0]] if matches else default


def field_name(obj, name):
    field(obj, name)
    return next((key for key in obj if key.casefold() == name.casefold()), name)


def public_key(encoded, expected_id=None):
    require(isinstance(encoded, str) and len(encoded) <= 256, "invalid_public_spki")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise AdmissionError("invalid_public_spki") from error
    # Canonical DER SubjectPublicKeyInfo: id-ecPublicKey, prime256v1, uncompressed point.
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
    require(len(raw) == 91 and raw.startswith(prefix), "canonical_p256_spki_required")
    x, y = int.from_bytes(raw[-64:-32], "big"), int.from_bytes(raw[-32:], "big")
    prime = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    require(x < prime and y < prime and (y * y - (x * x * x - 3 * x + b)) % prime == 0,
            "invalid_p256_public_point")
    require(base64.b64encode(raw).decode("ascii") == encoded, "noncanonical_public_spki")
    identity = hashlib.sha256(raw).hexdigest()
    require(expected_id is None or expected_id == identity, "public_spki_identity_mismatch")
    return {"DeviceId": identity, "PublicKeySpkiBase64": encoded}


def public_input(raw, role, is_json):
    require(role in ("controller", "companion"), "invalid_device_role")
    if not is_json:
        if raw.startswith(bytes.fromhex("30593013")):
            record = public_key(base64.b64encode(raw).decode("ascii"))
        else:
            try:
                record = public_key(raw.decode("ascii").strip())
            except UnicodeError as error:
                raise AdmissionError("invalid_public_spki") from error
    else:
        value = decode(raw)
        # Accept either portable public records or the documented public enrollment bundles.
        # A caller must extract enrollmentRequest from an MCP response explicitly.
        forbidden = ("private", "password", "secret", "token")
        require(not any(any(word in key.casefold() for word in forbidden) for key in value),
                "public_identity_only")
        declared = field(value, "Role")
        require(declared is None or declared == role, "public_role_mismatch")
        if "controllerSPKIBase64" in value:
            require(role == "controller", "public_role_mismatch")
            require(set(value) <= {"version", "authorizationSource", "authorizationReference", "controllerDeviceID",
                    "controllerSPKIBase64", "pairingID", "grantID", "fileGrantID", "rdpGrantID", "issuedAtUtc", "expiresAtUtc"},
                    "unsupported_public_identity_field")
            encoded, identity = value.get("controllerSPKIBase64"), value.get("controllerDeviceID")
        elif "peerSPKIBase64" in value:
            require(role == "companion", "public_role_mismatch")
            require(set(value) <= {"version", "name", "relayURL", "peerDeviceID", "peerSPKIBase64", "pairingID",
                    "grantID", "fileGrantID", "rdpGrantID", "allowWindows10TLS12", "installationState"},
                    "unsupported_public_identity_field")
            encoded, identity = value.get("peerSPKIBase64"), value.get("peerDeviceID")
        else:
            require({key.casefold() for key in value} <= {"deviceid", "publickeyspkibase64", "role", "peers"},
                    "unsupported_public_identity_field")
            encoded, identity = field(value, "PublicKeySpkiBase64"), field(value, "DeviceId")
        require(isinstance(identity, str), "public_device_id_required")
        record = public_key(encoded, identity)
    record.update(Role=role, Peers=[])
    return record


def registry(config, allow_empty=False):
    relay = field(config, "Relay")
    devices = field(relay, "Devices")
    maximum = field(relay, "MaxDevices", 64)
    companions = field(relay, "MaxCompanionDevices", 10)
    require(type(maximum) is int and 2 <= maximum <= 10000 and type(companions) is int
            and 1 <= companions <= maximum, "invalid_admission_capacity")
    require(isinstance(devices, list) and (allow_empty or devices) and len(devices) <= maximum,
            "device_capacity_exceeded")
    records = {}
    for device in devices:
        identity, role, peers = field(device, "DeviceId"), field(device, "Role"), field(device, "Peers")
        public_key(field(device, "PublicKeySpkiBase64"), identity)
        require(isinstance(identity, str) and identity not in records, "duplicate_device_identity")
        require(role in ("controller", "companion"), "invalid_device_role")
        require(isinstance(peers, list) and all(isinstance(peer, str) for peer in peers)
                and len(peers) <= min(128, maximum) and len(set(peers)) == len(peers), "invalid_peer_directory")
        records[identity] = device
    require(sum(field(item, "Role") == "companion" for item in devices) <= companions,
            "companion_capacity_exceeded")
    for identity, device in records.items():
        for peer in field(device, "Peers"):
            require(peer in records and field(records[peer], "Role") != field(device, "Role")
                    and identity in field(records[peer], "Peers"), "nonreciprocal_peer_relationship")
    return relay, devices, records


def merge(config, controller, companion):
    result = copy.deepcopy(config)
    _, devices, records = registry(result, allow_empty=True)
    require(controller["DeviceId"] != companion["DeviceId"], "distinct_device_identities_required")
    for incoming, role in ((controller, "controller"), (companion, "companion")):
        require(incoming["Role"] == role, "public_role_mismatch")
        public_key(incoming["PublicKeySpkiBase64"], incoming["DeviceId"])
        existing = records.get(incoming["DeviceId"])
        if existing:
            require(field(existing, "Role") == role, "existing_device_role_conflict")
            require(field(existing, "PublicKeySpkiBase64") == incoming["PublicKeySpkiBase64"],
                    "existing_device_key_conflict")
        else:
            existing = copy.deepcopy(incoming)
            devices.append(existing)
            records[incoming["DeviceId"]] = existing
    for source, peer in ((controller, companion), (companion, controller)):
        saved = records[source["DeviceId"]]
        peers = saved[field_name(saved, "Peers")]
        if peer["DeviceId"] not in peers:
            peers.append(peer["DeviceId"])
    registry(result)
    return result


def encode(value):
    return (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
