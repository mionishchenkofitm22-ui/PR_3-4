from __future__ import annotations

from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class RSAError(Exception): ...
class BadKey(RSAError): ...

def generate_keys(priv_path: Path, pub_path: Path, password: str, bits: int = 3072):
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    enc = serialization.BestAvailableEncryption(password.encode("utf-8"))
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    pem_pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path.write_bytes(pem_priv)
    pub_path.write_bytes(pem_pub)

def load_private(priv_path: Path, password: str):
    try:
        data = priv_path.read_bytes()
        return serialization.load_pem_private_key(data, password=password.encode("utf-8"))
    except Exception as e:
        raise BadKey("Cannot load private key (wrong password or format)") from e

def load_public(pub_path: Path):
    try:
        data = pub_path.read_bytes()
        return serialization.load_pem_public_key(data)
    except Exception as e:
        raise BadKey("Cannot load public key (wrong format)") from e

def sign_bytes(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

def verify_bytes(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

def encrypt_key(public_key, key_bytes: bytes) -> bytes:
    return public_key.encrypt(
        key_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

def decrypt_key(private_key, enc_key: bytes) -> bytes:
    return private_key.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
