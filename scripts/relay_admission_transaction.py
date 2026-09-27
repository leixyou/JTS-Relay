"""Durable candidate, backup and cooperative compare-and-swap publication."""
import contextlib
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import uuid

from relay_admission_public import AdmissionError, decode, encode, field, merge, registry, require
from relay_admission_metadata import read_attributes, restore_attributes

MAX_CONFIG_BYTES = 16 * 1024 * 1024


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_regular(path, limit=MAX_CONFIG_BYTES):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
                "regular_bounded_file_required")
        chunks = []
        count = 0
        while True:
            block = os.read(fd, min(65536, limit + 1 - count))
            if not block:
                break
            chunks.append(block)
            count += len(block)
            require(count <= limit, "file_size_limit")
        attributes = read_attributes(fd)
        after = os.fstat(fd)
        require(_stamp(before) == _stamp(after), "file_changed_during_read")
        value = dict(_stamp(after), xattrs=attributes)
        raw = b"".join(chunks)
        require(len(raw) == after.st_size, "file_changed_during_read")
        return raw, value
    finally:
        os.close(fd)


def _stamp(value):
    return dict(device=value.st_dev, inode=value.st_ino, mode=stat.S_IMODE(value.st_mode),
                uid=value.st_uid, gid=value.st_gid, size=value.st_size,
                mtimeNs=value.st_mtime_ns, ctimeNs=value.st_ctime_ns)


def _write_new(path, raw, metadata=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, "write_failed")
            view = view[count:]
        if metadata is not None:
            current = os.fstat(fd)
            if (current.st_uid, current.st_gid) != (metadata["uid"], metadata["gid"]):
                os.fchown(fd, metadata["uid"], metadata["gid"])
            os.fchmod(fd, metadata["mode"])
            restore_attributes(fd, metadata["xattrs"])
            # ACL xattrs can update permission bits. Do not silently change either.
            require(stat.S_IMODE(os.fstat(fd).st_mode) == metadata["mode"], "metadata_restore_failed")
            os.utime(fd, ns=(metadata["mtimeNs"], metadata["mtimeNs"]))
        os.fsync(fd)
    finally:
        os.close(fd)


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _path(path):
    path = Path(path)
    require(path.is_absolute() and path.name not in ("", ".", ".."), "absolute_config_path_required")
    require(path.parent.resolve() == path.parent, "symlinked_config_parent_not_supported")
    return path


@contextlib.contextmanager
def _lock(config):
    lock = config.with_name(config.name + ".admission.lock")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        value = os.fstat(fd)
        require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == os.geteuid()
                and stat.S_IMODE(value.st_mode) & 0o077 == 0, "unsafe_admission_lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AdmissionError("admission_operation_in_progress") from error
        yield
    finally:
        os.close(fd)


def prepare(config, controller, companion, output_directory=None):
    config = _path(config)
    with _lock(config):
        original, metadata = read_regular(config)
        candidate = encode(merge(decode(original), controller, companion))
        parent = _path(Path(output_directory)) if output_directory else config.parent
        require(parent.is_dir() and parent.resolve() == parent, "output_directory_required")
        transaction = parent / ("relay-admission-" + uuid.uuid4().hex)
        os.mkdir(transaction, 0o700)
        _write_new(transaction / "original.json", original)
        _write_new(transaction / "candidate.json", candidate)
        manifest = dict(version=1, config=str(config), state="prepared", originalSHA256=digest(original),
                        candidateSHA256=digest(candidate), originalMetadata=metadata,
                        controllerDeviceID=controller["DeviceId"], companionDeviceID=companion["DeviceId"])
        _write_new(transaction / "manifest.json", encode(manifest))
        _sync_directory(transaction)
        _sync_directory(parent)
        return _summary(transaction, manifest, changed=decode(original) != decode(candidate))


def _summary(transaction, manifest, **extra):
    return dict(state=manifest["state"], manifest=str(transaction / "manifest.json"),
                backup=str(transaction / "original.json"), candidate=str(transaction / "candidate.json"),
                originalSHA256=manifest["originalSHA256"], candidateSHA256=manifest["candidateSHA256"],
                serviceRestarted=False, **extra)


def _load_transaction(config, manifest_path):
    manifest_path = _path(manifest_path)
    require(manifest_path.name == "manifest.json", "manifest_name_required")
    directory = manifest_path.parent
    mode = directory.stat()
    require(mode.st_uid == os.geteuid() and stat.S_IMODE(mode.st_mode) == 0o700, "unsafe_transaction_directory")
    contents = {}
    for name in ("manifest.json", "original.json", "candidate.json"):
        raw, metadata = read_regular(directory / name)
        require(metadata["uid"] == os.geteuid() and metadata["mode"] == 0o600, "unsafe_transaction_file")
        contents[name] = raw
    manifest = decode(contents["manifest.json"])
    require(manifest.get("version") == 1 and manifest.get("config") == str(config)
            and manifest.get("state") in ("prepared", "applied", "rolledBack"), "invalid_manifest")
    original, candidate = contents["original.json"], contents["candidate.json"]
    require(digest(original) == manifest.get("originalSHA256") and digest(candidate) == manifest.get("candidateSHA256"),
            "transaction_content_changed")
    _, _, devices = registry(decode(candidate))
    controller = devices.get(manifest.get("controllerDeviceID"))
    companion = devices.get(manifest.get("companionDeviceID"))
    require(controller is not None and companion is not None, "invalid_manifest_identities")
    # Reconstruct only this reciprocal pair; candidate edits to TLS, quotas or other devices fail.
    pair = []
    for item in (controller, companion):
        pair.append({"DeviceId": field(item, "DeviceId"), "PublicKeySpkiBase64": field(item, "PublicKeySpkiBase64"),
                     "Role": field(item, "Role"), "Peers": []})
    require(merge(decode(original), *pair) == decode(candidate), "candidate_contains_unrelated_changes")
    return directory, manifest, original, candidate


def _publish(config, expected, expected_metadata, replacement, restored_metadata):
    current, metadata = read_regular(config)
    require(current == expected and metadata == expected_metadata, "configuration_compare_and_swap_failed")
    temporary = config.with_name("." + config.name + ".admission-" + uuid.uuid4().hex)
    try:
        _write_new(temporary, replacement, restored_metadata)
        # Serialize cooperating writers with flock, then verify content + inode + metadata immediately before rename.
        current, metadata = read_regular(config)
        require(current == expected and metadata == expected_metadata, "configuration_compare_and_swap_failed")
        os.replace(temporary, config)
        _sync_directory(config.parent)
    finally:
        temporary.unlink(missing_ok=True)
    actual, metadata = read_regular(config)
    require(actual == replacement, "published_configuration_changed")
    return metadata


def _save_manifest(directory, manifest):
    temporary = directory / (".manifest-" + uuid.uuid4().hex)
    _write_new(temporary, encode(manifest))
    os.replace(temporary, directory / "manifest.json")
    _sync_directory(directory)


def commit(config, manifest_path, rollback=False):
    config = _path(config)
    with _lock(config):
        directory, manifest, original, candidate = _load_transaction(config, manifest_path)
        current, metadata = read_regular(config)
        if rollback:
            require(manifest["state"] == "applied" and "appliedMetadata" in manifest, "transaction_not_applied")
            restored = _publish(config, candidate, manifest["appliedMetadata"], original, manifest["originalMetadata"])
            manifest.update(state="rolledBack", rollbackMetadata=restored)
        else:
            require(manifest["state"] in ("prepared", "applied"), "transaction_already_rolled_back")
            if manifest["state"] == "applied":
                require(current == candidate and metadata == manifest["appliedMetadata"], "configuration_compare_and_swap_failed")
                return _summary(directory, manifest, alreadyApplied=True)
            preserved = ("uid", "gid", "mode", "mtimeNs", "xattrs")
            if current == candidate and all(metadata[key] == manifest["originalMetadata"][key] for key in preserved):
                # A crash after atomic rename but before journal update is recoverable without replaying publication.
                manifest.update(state="applied", appliedMetadata=metadata)
                _save_manifest(directory, manifest)
                return _summary(directory, manifest, recoveredPublishedCandidate=True)
            applied = _publish(config, original, manifest["originalMetadata"], candidate, manifest["originalMetadata"])
            manifest.update(state="applied", appliedMetadata=applied)
        _save_manifest(directory, manifest)
        return _summary(directory, manifest)
