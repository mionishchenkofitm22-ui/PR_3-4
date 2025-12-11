from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# RSA key gen / save / load / OAEP / PSS sign

def gen_rsa(bits=3072):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return priv, priv.public_key()

def save_priv_pem(priv, path, password: str):
    enc = serialization.BestAvailableEncryption(password.encode())
    pem = priv.private_bytes(encoding=serialization.Encoding.PEM,
                             format=serialization.PrivateFormat.PKCS8,
                             encryption_algorithm=enc)
    open(path,'wb').write(pem)

def save_pub_pem(pub, path):
    pem = pub.public_bytes(encoding=serialization.Encoding.PEM,
                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
    open(path,'wb').write(pem)

def load_priv(path, password: str):
    return serialization.load_pem_private_key(open(path,'rb').read(), password=password.encode())

def load_pub(path):
    return serialization.load_pem_public_key(open(path,'rb').read())

def rsa_encrypt(pub, data: bytes) -> bytes:
    return pub.encrypt(data, asy_padding.OAEP(mgf=asy_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def rsa_decrypt(priv, ct: bytes) -> bytes:
    return priv.decrypt(ct, asy_padding.OAEP(mgf=asy_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def sign(priv, data: bytes) -> bytes:
    return priv.sign(data, asy_padding.PSS(mgf=asy_padding.MGF1(hashes.SHA256()), salt_length=asy_padding.PSS.MAX_LENGTH), hashes.SHA256())

def verify(pub, sig: bytes, data: bytes) -> bool:
    try:
        pub.verify(sig, data, asy_padding.PSS(mgf=asy_padding.MGF1(hashes.SHA256()), salt_length=asy_padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
