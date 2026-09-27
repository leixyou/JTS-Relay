import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from relay_admission_public import AdmissionError, decode, encode, merge, public_input, public_key, registry
from relay_admission_transaction import _lock, commit, prepare
from relay_admission_metadata import get_attribute, set_attribute


# SEC 2 P-256 generator and its double; public test points, not stored private keys.
POINTS = [
    ("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
     "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    ("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
     "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1")]


def identity(index, role, negate=False):
    x, y = POINTS[index]
    if negate:
        prime = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        y = f"{prime - int(y, 16):064x}"
    raw = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004" + x + y)
    return dict(DeviceId=hashlib.sha256(raw).hexdigest(), PublicKeySpkiBase64=base64.b64encode(raw).decode(), Role=role, Peers=[])


def configuration():
    return {"Kestrel": {"Endpoints": {"Https": {"Certificate": {"KeyPath": "/never/open/tls.key"}}}},
            "Relay": {"MaxDevices": 64, "MaxCompanionDevices": 10, "Devices": [], "DatabasePath": "/var/lib/relay.sqlite"},
            "UnrelatedSetting": {"keep": [1, 2, 3]}}


class AdmissionValidationTests(unittest.TestCase):
    def setUp(self):
        self.controller = identity(0, "controller")
        self.companion = identity(1, "companion")

    def test_public_spki_and_enrollment_formats(self):
        controller = dict(controllerDeviceID=self.controller["DeviceId"], controllerSPKIBase64=self.controller["PublicKeySpkiBase64"])
        companion = dict(peerDeviceID=self.companion["DeviceId"], peerSPKIBase64=self.companion["PublicKeySpkiBase64"])
        self.assertEqual(public_input(encode(controller), "controller", True), self.controller)
        self.assertEqual(public_input(encode(companion), "companion", True), self.companion)
        self.assertEqual(public_input(base64.b64decode(self.controller["PublicKeySpkiBase64"]), "controller", False), self.controller)
        with self.assertRaisesRegex(AdmissionError, "public_role_mismatch"):
            public_input(encode(controller), "companion", True)
        controller["privateKey"] = "must not be accepted"
        with self.assertRaisesRegex(AdmissionError, "public_identity_only"):
            public_input(encode(controller), "controller", True)

    def test_malformed_points_hashes_and_duplicate_json_fail(self):
        raw = bytearray(base64.b64decode(self.controller["PublicKeySpkiBase64"]))
        raw[-1] ^= 1
        with self.assertRaisesRegex(AdmissionError, "invalid_p256_public_point"):
            public_key(base64.b64encode(raw).decode())
        with self.assertRaisesRegex(AdmissionError, "public_spki_identity_mismatch"):
            public_key(self.controller["PublicKeySpkiBase64"], "0" * 64)
        with self.assertRaisesRegex(AdmissionError, "duplicate_json_property"):
            decode(b'{"Relay": {}, "Relay": {}}')

    def test_merge_is_idempotent_preserves_case_and_other_configuration(self):
        config = configuration()
        merged = merge(config, self.controller, self.companion)
        self.assertEqual(merged["Kestrel"], config["Kestrel"])
        self.assertEqual(merged["UnrelatedSetting"], config["UnrelatedSetting"])
        self.assertEqual(len(config["Relay"]["Devices"]), 0)
        self.assertEqual(merge(merged, self.controller, self.companion), merged)
        # The live .NET binder accepts Pascal/camel case; preserve existing record spelling.
        merged["Relay"]["Devices"] = [{key[0].lower() + key[1:]: value for key, value in row.items()}
                                       for row in merged["Relay"]["Devices"]]
        self.assertEqual(merge(merged, self.controller, self.companion), merged)

    def test_role_duplicates_capacity_and_reciprocal_peers_fail(self):
        valid = merge(configuration(), self.controller, self.companion)
        bad = copy.deepcopy(valid); bad["Relay"]["Devices"].append(copy.deepcopy(bad["Relay"]["Devices"][0]))
        with self.assertRaisesRegex(AdmissionError, "duplicate_device_identity"):
            registry(bad)
        bad = copy.deepcopy(valid); bad["Relay"]["Devices"][0]["Peers"] = []
        with self.assertRaisesRegex(AdmissionError, "nonreciprocal_peer_relationship"):
            merge(bad, self.controller, self.companion)
        bad = configuration(); bad["Relay"]["MaxDevices"] = 1
        with self.assertRaisesRegex(AdmissionError, "invalid_admission_capacity"):
            merge(bad, self.controller, self.companion)
        swapped = identity(0, "companion")
        with self.assertRaisesRegex(AdmissionError, "public_role_mismatch"):
            merge(configuration(), swapped, self.companion)
        bad = copy.deepcopy(valid); bad["Relay"]["Devices"][0]["Peers"] *= 2
        with self.assertRaisesRegex(AdmissionError, "invalid_peer_directory"):
            registry(bad)

    def test_preserves_existing_devices_and_enforces_remaining_capacity(self):
        previous = merge(configuration(), self.controller, self.companion)
        extra_controller, extra_companion = identity(0, "controller", True), identity(1, "companion", True)
        combined = merge(previous, extra_controller, extra_companion)
        self.assertEqual(combined["Relay"]["Devices"][:2], previous["Relay"]["Devices"])
        previous["Relay"]["MaxDevices"] = 3
        previous["Relay"]["MaxCompanionDevices"] = 3
        with self.assertRaisesRegex(AdmissionError, "device_capacity_exceeded"):
            merge(previous, extra_controller, extra_companion)
        previous["Relay"]["MaxDevices"] = 64
        previous["Relay"]["MaxCompanionDevices"] = 1
        with self.assertRaisesRegex(AdmissionError, "companion_capacity_exceeded"):
            merge(previous, extra_controller, extra_companion)


class AdmissionTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.config = self.root / "relay.json"
        self.original = encode(configuration())
        self.config.write_bytes(self.original)
        self.config.chmod(0o640)
        self.controller, self.companion = identity(0, "controller"), identity(1, "companion")

    def prepared(self):
        return prepare(self.config, self.controller, self.companion)

    def test_prepare_is_reviewable_and_does_not_touch_active_config(self):
        before = self.config.stat()
        result = self.prepared()
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.config.stat().st_ino, before.st_ino)
        self.assertEqual(Path(result["backup"]).read_bytes(), self.original)
        self.assertEqual(stat.S_IMODE(Path(result["manifest"]).parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(Path(result["backup"]).stat().st_mode), 0o600)
        self.assertEqual(result["state"], "prepared")
        self.assertFalse(result["serviceRestarted"])

    def test_apply_and_rollback_preserve_metadata_and_xattrs(self):
        attribute = "user.jts-admission-test" if sys.platform != "darwin" else "jts-admission-test"
        with self.config.open("rb") as source:
            set_attribute(source.fileno(), attribute, b"public-permission-marker")
        before = self.config.stat()
        result = self.prepared()
        applied = commit(self.config, result["manifest"])
        after = self.config.stat()
        self.assertEqual((after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
                         (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)))
        with self.config.open("rb") as source:
            self.assertEqual(get_attribute(source.fileno(), attribute), b"public-permission-marker")
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(applied["state"], "applied")
        self.assertTrue(commit(self.config, result["manifest"])["alreadyApplied"])
        self.assertEqual(commit(self.config, result["manifest"], rollback=True)["state"], "rolledBack")
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_changed_content_or_inode_blocks_compare_and_swap(self):
        result = self.prepared()
        self.config.write_bytes(self.original + b" ")
        with self.assertRaisesRegex(AdmissionError, "configuration_compare_and_swap_failed"):
            commit(self.config, result["manifest"])
        self.config.write_bytes(self.original)
        second = self.prepared()
        replacement = self.root / "replacement"
        replacement.write_bytes(self.original); replacement.chmod(0o640)
        os.replace(replacement, self.config)
        with self.assertRaisesRegex(AdmissionError, "configuration_compare_and_swap_failed"):
            commit(self.config, second["manifest"])

    def test_rollback_does_not_overwrite_a_later_edit(self):
        result = self.prepared()
        commit(self.config, result["manifest"])
        new = self.config.read_bytes() + b"\n"
        self.config.write_bytes(new)
        with self.assertRaisesRegex(AdmissionError, "configuration_compare_and_swap_failed"):
            commit(self.config, result["manifest"], rollback=True)
        self.assertEqual(self.config.read_bytes(), new)

    def test_candidate_cannot_modify_tls_even_with_updated_checksum(self):
        result = self.prepared()
        candidate = Path(result["candidate"])
        value = decode(candidate.read_bytes()); value["Kestrel"] = {}
        candidate.write_bytes(encode(value))
        manifest = Path(result["manifest"])
        value = decode(manifest.read_bytes()); value["candidateSHA256"] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        manifest.write_bytes(encode(value))
        with self.assertRaisesRegex(AdmissionError, "candidate_contains_unrelated_changes"):
            commit(self.config, manifest)

    def test_lock_and_symlink_inputs_fail_closed(self):
        result = self.prepared()
        with _lock(self.config):
            with self.assertRaisesRegex(AdmissionError, "admission_operation_in_progress"):
                commit(self.config, result["manifest"])
        alias = self.root / "alias.json"; alias.symlink_to(self.config)
        with self.assertRaises(OSError):
            prepare(alias, self.controller, self.companion)

    def test_crash_after_publication_recovers_without_republishing(self):
        result = self.prepared()
        with mock.patch("relay_admission_transaction._save_manifest", side_effect=OSError("interrupted")):
            with self.assertRaises(OSError):
                commit(self.config, result["manifest"])
        inode = self.config.stat().st_ino
        recovered = commit(self.config, result["manifest"])
        self.assertTrue(recovered["recoveredPublishedCandidate"])
        self.assertEqual(self.config.stat().st_ino, inode)
        commit(self.config, result["manifest"], rollback=True)
        self.assertEqual(self.config.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main()
