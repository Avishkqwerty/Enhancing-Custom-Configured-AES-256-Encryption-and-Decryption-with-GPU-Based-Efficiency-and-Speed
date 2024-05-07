import hashlib
import hmac
import scrypt

def hkdf_scrypt(password, salt, length, n, r, p):
    # HKDF extraction step
    prk = hmac.new(salt.encode(), password.encode(), hashlib.sha256).digest()

    # HKDF expansion step
    info = b'Scrypt key derivation'
    t = b''
    okm = b''
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([len(t) + 1]), hashlib.sha256).digest()
        okm += scrypt.hash(t, salt.encode(), n, r, p, length)

    return okm[:length]

# Prompt the user for inputs
password = input("Enter the password: ")
salt = input("Enter the salt: ")
length = int(input("Enter the desired key length in bytes: "))
n = int(input("Enter the value for 'n': "))
r = int(input("Enter the value for 'r': "))
p = int(input("Enter the value for 'p': "))

# Call the hkdf_scrypt function with user inputs
derived_key = hkdf_scrypt(password, salt, length, n, r, p)
print("Derived Key:", derived_key.hex())
