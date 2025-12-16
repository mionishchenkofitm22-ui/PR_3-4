from __future__ import annotations

import base64, json, os
from pathlib import Path
from typing import Literal

from .crypto_sym import KeyMaterial, encrypt_bytes, decrypt_bytes
from .crypto_rsa import load_public, load_private, encrypt_key, decrypt_key

Mode = Literal["gcm", "cbc"]

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def write_container(path_out: Path, header: dict, ciphertext: bytes):
    path_out.parent.mkdir(parents=True, exist_ok=True)
    path_out.write_bytes(json.dumps(header, ensure_ascii=False).encode("utf-8") + b"\n" + ciphertext)

def read_container(path_in: Path) -> tuple[dict, bytes]:
    raw = path_in.read_bytes()
    line, body = raw.split(b"\n", 1)
    header = json.loads(line.decode("utf-8"))
    return header, body

def hybrid_encrypt(pub_pem: Path, data: bytes, mode: Mode = "gcm") -> tuple[dict, bytes]:
    pub = load_public(pub_pem)

    # Generate one-time symmetric key material (master key + salt)
    salt = os.urandom(16)
    master_key = os.urandom(32)
    km = KeyMaterial(label="hybrid-ephemeral", version=1, salt=salt, master_key=master_key)

    sym_header, ciphertext = encrypt_bytes(data, km, mode=mode)

    enc_key_blob = encrypt_key(pub, salt + master_key)  # pack salt||master for recipient
    header = {
        "kind": "hybrid",
        "mode": sym_header["mode"],
        "enc_key_b64": _b64e(enc_key_blob),
        "salt_b64": sym_header["salt_b64"],
        "key_bytes_len": len(salt + master_key),
    }
    # carry mode-specific fields
    header.update({k: v for k, v in sym_header.items() if k.endswith("_b64") and k not in ("salt_b64",)})
    return header, ciphertext

def hybrid_decrypt(priv_pem: Path, password: str, header: dict, ciphertext: bytes) -> bytes:
    priv = load_private(priv_pem, password=password)
    enc_key_blob = _b64d(header["enc_key_b64"])
    key_bytes = decrypt_key(priv, enc_key_blob)
    if len(key_bytes) < 48:
        raise ValueError("Decrypted key blob too short")
    salt, master_key = key_bytes[:16], key_bytes[16:48]
    km = KeyMaterial(label="hybrid-ephemeral", version=1, salt=salt, master_key=master_key)

    # Reconstruct sym header for decrypt_bytes()
    sym_header = {"mode": header["mode"], "salt_b64": header["salt_b64"]}
    if header["mode"] == "gcm":
        sym_header["nonce_b64"] = header["nonce_b64"]
        sym_header["tag_b64"] = header["tag_b64"]
    else:
        sym_header["iv_b64"] = header["iv_b64"]
        sym_header["hmac_b64"] = header["hmac_b64"]
    return decrypt_bytes(sym_header, ciphertext, km)
