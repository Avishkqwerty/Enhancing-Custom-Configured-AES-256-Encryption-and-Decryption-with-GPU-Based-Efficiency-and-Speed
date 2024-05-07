
#ANS X9.63-2001 is a standard for key agreement and key derivation using 
#HMAC (Hash-based Message Authentication Code) and the HMAC-based Extract-and-Expand Key Derivation Function (HKDF) construction.

import hashlib
import hmac
import os

def ans_x9_63_2001_kdf(password, salt, length):
    # Initialize variables
    prk = hmac.new(password.encode(), salt.encode(), hashlib.sha256).digest()
    output = b''
    i = 1

    # Iteratively hash and concatenate until the desired key length is reached
    while len(output) < length:
        t = hmac.new(prk, (t if len(output) > 0 else b'') + salt.encode() + bytes([i]), hashlib.sha256).digest()
        output += t
        i += 1

    return output[:length]

# Prompt the user for inputs
password = input("Enter the password: ")
salt = input("Enter the salt: ")
length = int(input("Enter the desired key length in bytes: "))

# Call the ans_x9_63_2001_kdf function with user inputs
derived_key = ans_x9_63_2001_kdf(password, salt, length)
print("Derived Key:", derived_key.hex())
