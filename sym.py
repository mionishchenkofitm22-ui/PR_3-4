import os, json, struct, secrets
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac as hmac_lib

MAGIC = b'CSYM'
VERSION = 1

CHUNK = 1024*1024

class SymKeyStore:
    def __init__(self, path='keystore.json'):
        self.path = path
        self.db = {'keys': []}
        if os.path.exists(path):
            self.db = json.load(open(path,'r',encoding='utf-8'))

    def new(self, label: str, bits: int = 256):
        key = secrets.token_bytes(bits//8)
        key_id = secrets.token_hex(8)
        meta = {'label': label, 'key_id': key_id, 'bits': bits, 'created': int(secrets.randbelow(2**31)), 'uses': 0}
        self.db['keys'].append(meta)
        self.save()
        # Ключ **не** зберігаємо у файлі; для демо повертаємо його виклику
        return meta, key

    def save(self):
        json.dump(self.db, open(self.path,'w',encoding='utf-8'), ensure_ascii=False, indent=2)


def _pack_header(h: dict) -> bytes:
    blob = json.dumps(h, separators=(',',':')).encode('utf-8')
    return MAGIC + struct.pack('>H', len(blob)) + blob

def _unpack_header(fp) -> dict:
    magic = fp.read(4)
    if magic != MAGIC:
        raise ValueError('bad magic')
    (hl,) = struct.unpack('>H', fp.read(2))
    return json.loads(fp.read(hl).decode('utf-8'))


def encrypt_gcm(in_path: str, out_path: str, key: bytes, aad: Optional[bytes]=None):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    h = {'v': VERSION, 'mode':'GCM', 'nonce': nonce.hex(), 'alg':'AES-%d-GCM'% (len(key)*8)}
    header = _pack_header(h)
    data = open(in_path,'rb').read()
    ct = aesgcm.encrypt(nonce, data, header if aad is None else aad)
    with open(out_path,'wb') as f:
        f.write(header)
        f.write(ct)


def decrypt_gcm(in_path: str, out_path: str, key: bytes, aad: Optional[bytes]=None):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    with open(in_path,'rb') as f:
        hdr = _unpack_header(f)
        data = f.read()
    nonce = bytes.fromhex(hdr['nonce'])
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, data, _pack_header(hdr) if aad is None else aad)
    open(out_path,'wb').write(pt)


def encrypt_cbc_hmac(in_path: str, out_path: str, key: bytes):
    iv = secrets.token_bytes(16)
    enc_key = key
    mac_key = secrets.token_bytes(32)
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    enc = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    h = {'v': VERSION, 'mode':'CBC-HMAC', 'iv': iv.hex(), 'alg':'AES-%d-CBC'% (len(enc_key)*8), 'mac':'HMAC-SHA256'}
    header = _pack_header(h)
    mac = hmac_lib.HMAC(mac_key, hashes.SHA256())
    mac.update(header); mac.update(iv)
    with open(in_path,'rb') as fi, open(out_path,'wb') as fo:
        fo.write(header); fo.write(iv)
        while True:
            chunk = fi.read(CHUNK)
            if not chunk: break
            c = enc.update(padder.update(chunk))
            if c:
                fo.write(c); mac.update(c)
        c = enc.update(padder.finalize()) + enc.finalize()
        if c:
            fo.write(c); mac.update(c)
        fo.write(mac.finalize())


def decrypt_cbc_hmac(in_path: str, out_path: str, key: bytes):
    with open(in_path,'rb') as f:
        hdr = _unpack_header(f)
        iv = bytes.fromhex(hdr['iv'])
        body = f.read()
    tag = body[-32:]; data = body[:-32]
    mac_key = b'\x00'*32  # демо: у реальному рішенні mac_key зберігати/обмінювати безпечно
    mac = hmac_lib.HMAC(mac_key, hashes.SHA256()); mac.update(_pack_header(hdr)); mac.update(iv); mac.update(data)
    mac.verify(tag)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor(); unpad = padding.PKCS7(128).unpadder()
    pt = unpad.update(dec.update(data) + dec.finalize()) + unpad.finalize()
    open(out_path,'wb').write(pt)
