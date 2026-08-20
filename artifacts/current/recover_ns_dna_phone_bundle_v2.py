#!/usr/bin/env python3
"""Authenticate, decrypt, verify, and safely extract an NS DNA v2 envelope."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import tarfile
import tempfile

SCHEMA = "ns_dna_phone_recovery_envelope_v2"
INFO = b"ns-dna-phone-recovery-v2"
MAGIC = b"NSDNA2\x00"
TOP_LEVEL_KEYS = {"protected", "ephemeral_public_key_der_b64", "iv_b64", "ciphertext_b64", "tag_b64"}
PROTECTED_KEYS = {"schema", "recipient", "source_archive", "internal_manifest", "crypto", "generated_at_utc", "ephemeral_public_key_fingerprint_sha256"}


def b64d(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("invalid base64 field")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("invalid base64 field") from exc


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def run(command: list[str], *, data: bytes | None = None) -> bytes:
    result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ValueError("openssl operation failed")
    return result.stdout


def hkdf(shared: bytes, length: int = 64) -> bytes:
    prk = hmac.new(b"\x00" * 32, shared, hashlib.sha256).digest()
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + INFO + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def exact_structure(protected: object) -> dict:
    if not isinstance(protected, dict) or set(protected) != PROTECTED_KEYS:
        raise ValueError("protected metadata structure mismatch")
    expected_nested = {
        "recipient": {"device_id", "fingerprint_sha256"},
        "source_archive": {"name", "sha256", "bytes"},
        "internal_manifest": {"sha256", "file_count"},
        "crypto": {"ecdh", "kdf", "hkdf_info", "cipher", "authentication", "composition"},
    }
    for key, keys in expected_nested.items():
        if not isinstance(protected[key], dict) or set(protected[key]) != keys:
            raise ValueError("protected metadata structure mismatch")
    if protected["schema"] != SCHEMA:
        raise ValueError("envelope schema mismatch")
    expected_crypto = {
        "ecdh": "P-256", "kdf": "HKDF-SHA256", "hkdf_info": INFO.decode("ascii"),
        "cipher": "AES-256-CTR", "authentication": "HMAC-SHA256", "composition": "encrypt-then-MAC",
    }
    if protected["crypto"] != expected_crypto:
        raise ValueError("crypto suite mismatch")
    return protected


def safe_name(name: object) -> bool:
    if not isinstance(name, str) or not name or "\\" in name:
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and str(path) == name


def derive_material(private_key: Path, ephemeral_der: bytes, expected_recipient_fingerprint: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="ns-dna-recover-v2-") as temp_name:
        temp = Path(temp_name)
        peer_der = temp / "ephemeral-public.der"
        peer_pem = temp / "ephemeral-public.pem"
        peer_der.write_bytes(ephemeral_der)
        public_der = run(["openssl", "pkey", "-in", str(private_key), "-pubout", "-outform", "DER"])
        if not hmac.compare_digest(hashlib.sha256(public_der).hexdigest(), expected_recipient_fingerprint):
            raise ValueError("private key does not match recipient fingerprint")
        peer_pem.write_bytes(run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(peer_der), "-pubout"]))
        shared = run(["openssl", "pkeyutl", "-derive", "-inkey", str(private_key), "-peerkey", str(peer_pem)])
    return hkdf(shared)


def parse_plaintext(plaintext: bytes, protected: dict) -> tuple[bytes, dict]:
    if not plaintext.startswith(MAGIC) or len(plaintext) < len(MAGIC) + 8:
        raise ValueError("decrypted container format mismatch")
    manifest_length = struct.unpack(">Q", plaintext[len(MAGIC):len(MAGIC) + 8])[0]
    start = len(MAGIC) + 8
    end = start + manifest_length
    if end > len(plaintext):
        raise ValueError("decrypted container truncated")
    manifest_bytes = plaintext[start:end]
    archive = plaintext[end:]
    if hashlib.sha256(manifest_bytes).hexdigest() != protected["internal_manifest"]["sha256"]:
        raise ValueError("internal manifest SHA256 mismatch")
    try:
        manifest = json.loads(manifest_bytes)
    except Exception as exc:
        raise ValueError("invalid internal manifest") from exc
    source = protected["source_archive"]
    if hashlib.sha256(archive).hexdigest() != source["sha256"] or len(archive) != source["bytes"]:
        raise ValueError("source archive SHA256 or size mismatch")
    if manifest.get("archive_sha256") != source["sha256"] or manifest.get("archive_bytes") != source["bytes"]:
        raise ValueError("internal manifest archive binding mismatch")
    files = manifest.get("files")
    if not isinstance(files, list) or manifest.get("file_count") != len(files) or len(files) != protected["internal_manifest"]["file_count"]:
        raise ValueError("internal manifest file count mismatch")
    return archive, manifest


def verify_and_extract_archive(archive: bytes, manifest: dict, destination: Path) -> None:
    if destination.exists():
        raise FileExistsError("recovery target already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    expected: dict[str, dict] = {}
    for item in manifest["files"]:
        if not isinstance(item, dict):
            raise ValueError("invalid manifest member")
        name = item.get("path")
        if not safe_name(name) or name in expected:
            raise ValueError("unsafe or duplicate manifest member")
        if not isinstance(item.get("size"), int) or item["size"] < 0 or not isinstance(item.get("sha256"), str) or len(item["sha256"]) != 64:
            raise ValueError("invalid manifest member metadata")
        expected[name] = item
    with tempfile.TemporaryDirectory(prefix="ns-dna-archive-v2-") as archive_temp_name:
        archive_path = Path(archive_temp_name) / "source.tar.gz"
        archive_path.write_bytes(archive)
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getmembers()
            names = [member.name for member in members]
            if names != sorted(names) or set(names) != set(expected) or len(names) != len(expected):
                raise ValueError("archive member allowlist mismatch")
            for member in members:
                if not member.isfile() or member.issym() or member.islnk() or member.isdev() or not safe_name(member.name):
                    raise ValueError("unsafe archive member type")
                item = expected[member.name]
                if member.size != item["size"]:
                    raise ValueError("archive member size mismatch")
                stream = tar.extractfile(member)
                if stream is None:
                    raise ValueError("archive member unreadable")
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                if digest.hexdigest() != item["sha256"]:
                    raise ValueError("archive member SHA256 mismatch")
    with tempfile.TemporaryDirectory(prefix=".ns-dna-stage-v2-", dir=destination.parent) as stage_name:
        stage = Path(stage_name)
        with tempfile.TemporaryDirectory(prefix="ns-dna-archive-v2-") as archive_temp_name:
            archive_path = Path(archive_temp_name) / "source.tar.gz"
            archive_path.write_bytes(archive)
            with tarfile.open(archive_path, "r:gz") as tar:
                for name in sorted(expected):
                    member = tar.getmember(name)
                    source = tar.extractfile(member)
                    if source is None:
                        raise ValueError("archive member unreadable during extraction")
                    target = stage.joinpath(*PurePosixPath(name).parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as output:
                        shutil.copyfileobj(source, output)
                    target.chmod(member.mode & 0o777)
        os.replace(stage, destination)


def recover(envelope_path: Path, private_key: Path, destination: Path) -> dict:
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    if not isinstance(envelope, dict) or set(envelope) != TOP_LEVEL_KEYS:
        raise ValueError("envelope structure mismatch")
    protected = exact_structure(envelope["protected"])
    ephemeral_der = b64d(envelope["ephemeral_public_key_der_b64"])
    if hashlib.sha256(ephemeral_der).hexdigest() != protected["ephemeral_public_key_fingerprint_sha256"]:
        raise ValueError("ephemeral public key fingerprint mismatch")
    iv = b64d(envelope["iv_b64"])
    ciphertext = b64d(envelope["ciphertext_b64"])
    tag = b64d(envelope["tag_b64"])
    if len(iv) != 16 or len(tag) != 32:
        raise ValueError("invalid IV or tag length")
    material = derive_material(private_key, ephemeral_der, protected["recipient"]["fingerprint_sha256"])
    expected_tag = hmac.new(material[32:], canonical(protected) + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("envelope authentication failed")
    plaintext = run(["openssl", "enc", "-d", "-aes-256-ctr", "-K", material[:32].hex(), "-iv", iv.hex()], data=ciphertext)
    archive, manifest = parse_plaintext(plaintext, protected)
    verify_and_extract_archive(archive, manifest, destination)
    return {"result": "PASS", "file_count": manifest["file_count"], "recovery_target": str(destination)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("envelope", type=Path)
    parser.add_argument("private_key", type=Path)
    parser.add_argument("recovery_target", type=Path)
    args = parser.parse_args()
    try:
        result = recover(args.envelope, args.private_key, args.recovery_target)
    except Exception as exc:
        print(json.dumps({"result": "DENY", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
