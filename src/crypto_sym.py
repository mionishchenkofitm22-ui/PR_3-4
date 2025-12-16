from __future__ import annotations

import base64, json, os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional, Tuple

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

Mode = Literal["gcm", "cbc"]

KEYSTORE_PATH = Path("keys/keystore.json")

class CryptoError(Exception): ...
class IntegrityError(CryptoError): ...
class KeyNotFound(CryptoError): ...
class BadFormat(CryptoError): ...

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

@dataclass
class KeyMaterial:
    label: str
    version: int
    salt: bytes
    master_key: bytes  # 32 bytes

    def derive(self) -> tuple[bytes, bytes]:
        # HKDF with salt -> enc_key (32) and mac_key (32)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=self.salt,
            info=f"PR3-4:{self.label}:v{self.version}".encode("utf-8"),
        )
        okm = hkdf.derive(self.master_key)
        return okm[:32], okm[32:]

class KeyStore:
    def __init__(self, path: Path = KEYSTORE_PATH):
        self.path = path

    def _load(self) -> dict:
        if not self.path.exists():
            return {"labels": {}}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, data: dict):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Best effort: restrict permissions (Unix)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except Exception:
            pass

    def new_key(self, label: str) -> KeyMaterial:
        data = self._load()
        labels = data.setdefault("labels", {})
        entry = labels.setdefault(label, {"versions": []})
        version = len(entry["versions"]) + 1

        salt = os.urandom(16)
        master_key = os.urandom(32)

        entry["versions"].append({
            "version": version,
            "salt_b64": _b64e(salt),
            "master_key_b64": _b64e(master_key),
        })
        self._save(data)
        return KeyMaterial(label=label, version=version, salt=salt, master_key=master_key)

    def get(self, label: str, version: Optional[int] = None) -> KeyMaterial:
        data = self._load()
        labels = data.get("labels", {})
        if label not in labels or not labels[label].get("versions"):
            raise KeyNotFound(f"Key label not found: {label}")
        versions = labels[label]["versions"]
        item = None
        if version is None:
            item = versions[-1]
        else:
            for v in versions:
                if int(v["version"]) == int(version):
                    item = v
                    break
        if not item:
            raise KeyNotFound(f"Key version not found: {label} v{version}")
        return KeyMaterial(
            label=label,
            version=int(item["version"]),
            salt=_b64d(item["salt_b64"]),
            master_key=_b64d(item["master_key_b64"]),
        )

def encrypt_bytes(plain: bytes, km: KeyMaterial, mode: Mode) -> tuple[dict, bytes]:
    enc_key, mac_key = km.derive()
    if mode == "gcm":
        nonce = os.urandom(12)
        aead = AESGCM(enc_key)
        ct = aead.encrypt(nonce, plain, None)  # ct includes tag at end
        # split tag for clarity
        ciphertext, tag = ct[:-16], ct[-16:]
        header = {
            "mode": "gcm",
            "key_label": km.label,
            "key_version": km.version,
            "salt_b64": _b64e(km.salt),
            "nonce_b64": _b64e(nonce),
            "tag_b64": _b64e(tag),
        }
        return header, ciphertext

    if mode == "cbc":
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plain) + padder.finalize()
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()

        h = hmac.HMAC(mac_key, hashes.SHA256())
        h.update(iv + ciphertext)
        tag = h.finalize()

        header = {
            "mode": "cbc",
            "key_label": km.label,
            "key_version": km.version,
            "salt_b64": _b64e(km.salt),
            "iv_b64": _b64e(iv),
            "hmac_b64": _b64e(tag),
        }
        return header, ciphertext

    raise BadFormat(f"Unknown mode: {mode}")

def decrypt_bytes(header: dict, ciphertext: bytes, km: KeyMaterial) -> bytes:
    mode = header.get("mode")
    enc_key, mac_key = km.derive()

    if mode == "gcm":
        nonce = _b64d(header["nonce_b64"])
        tag = _b64d(header["tag_b64"])
        aead = AESGCM(enc_key)
        try:
            pt = aead.decrypt(nonce, ciphertext + tag, None)
        except Exception as e:
            raise IntegrityError("GCM authentication failed") from e
        return pt

    if mode == "cbc":
        iv = _b64d(header["iv_b64"])
        tag = _b64d(header["hmac_b64"])

        h = hmac.HMAC(mac_key, hashes.SHA256())
        h.update(iv + ciphertext)
        try:
            h.verify(tag)
        except Exception as e:
            raise IntegrityError("HMAC verification failed") from e

        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        try:
            pt = unpadder.update(padded) + unpadder.finalize()
        except Exception as e:
            raise BadFormat("Bad padding (corrupted ciphertext)") from e
        return pt

    raise BadFormat(f"Unknown mode: {mode}")

def write_container(path_out: Path, header: dict, ciphertext: bytes):
    path_out.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(header, ensure_ascii=False).encode("utf-8") + b"\n" + ciphertext
    path_out.write_bytes(data)

def read_container(path_in: Path) -> tuple[dict, bytes]:
    raw = path_in.read_bytes()
    if b"\n" not in raw:
        raise BadFormat("Container missing header delimiter")
    line, body = raw.split(b"\n", 1)
    try:
        header = json.loads(line.decode("utf-8"))
    except Exception as e:
        raise BadFormat("Invalid JSON header") from e
    return header, body
