import hashlib
import hmac
import scrypt

def hkdf_scrypt(password, salt, length, n, r, p):
    # HKDF extraction step
    prk = hmac.new(salt, password, hashlib.sha256).digest()

    # HKDF expansion step
    info = b'Scrypt key derivation'
    t = b''
    okm = b''
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([len(t) + 1]), hashlib.sha256).digest()
        okm += scrypt.hash(t, salt, n=n, r=r, p=p, dklen=length)

    return okm[:length]