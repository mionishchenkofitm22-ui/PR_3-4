import os, json, struct, secrets
from typing import Optional
from asym import rsa_encrypt, rsa_decrypt, load_priv, load_pub
from sym import encrypt_gcm, decrypt_gcm, _pack_header, _unpack_header

MAGIC = b'CHYB'
VERSION = 1

# File: MAGIC|HDRLEN|HEADER(JSON:{v,mode,pubfp,alg,nonce?})|RSA_ENC_KEY|SYM_CIPHERTEXT

def _pack(h: dict, rsa_key_ct: bytes, payload: bytes) -> bytes:
    header = _pack_header(h)
    return header + len(rsa_key_ct).to_bytes(2,'big') + rsa_key_ct + payload

def _unpack(fp):
    hdr = _unpack_header(fp)
    ln = int.from_bytes(fp.read(2),'big')
    kct = fp.read(ln)
    body = fp.read()
    return hdr, kct, body


def encrypt_hybrid(pub_pem_path: str, in_path: str, out_path: str):
    pub = load_pub(pub_pem_path)
    # 1) random AES-256 key
    aes_key = secrets.token_bytes(32)
    # 2) RSA-OAEP wrap
    kct = rsa_encrypt(pub, aes_key)
    # 3) AES-GCM encrypt data, embedding header as AAD
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(aes_key)
    header = {'v': VERSION, 'mode':'HYBRID-GCM', 'alg':'AES-256-GCM+RSA-OAEP', 'nonce': nonce.hex()}
    aad = json.dumps(header, separators=(',',':')).encode()
    data = open(in_path,'rb').read()
    ct = aesgcm.encrypt(nonce, data, aad)
    with open(out_path,'wb') as f:
        f.write(b'CHYB' + len(aad).to_bytes(2,'big') + aad)
        f.write(len(kct).to_bytes(2,'big') + kct)
        f.write(ct)


def decrypt_hybrid(priv_pem_path: str, password: str, in_path: str, out_path: str):
    with open(in_path,'rb') as f:
        magic = f.read(4)
        if magic != b'CHYB': raise ValueError('bad magic')
        hl = int.from_bytes(f.read(2),'big')
        aad = f.read(hl)
        kl = int.from_bytes(f.read(2),'big')
        kct = f.read(kl)
        body = f.read()
    header = json.loads(aad.decode())
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    priv = load_priv(priv_pem_path, password)
    aes_key = rsa_decrypt(priv, kct)
    nonce = bytes.fromhex(header['nonce'])
    pt = AESGCM(aes_key).decrypt(nonce, body, aad)
    open(out_path,'wb').write(pt)
