import hashlib
import hmac
import scrypt
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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

def encrypt_file(file_path, key):
    # Read the file contents
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Create AES cipher object with key and mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Pad the plaintext to match AES block size
    padded_plaintext = pad(plaintext, AES.block_size)

    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    # Write the encrypted data back to the file
    with open(file_path, 'wb') as file:
        file.write(ciphertext)

def decrypt_file(file_path, key):
    # Read the file contents
    with open(file_path, 'rb') as file:
        ciphertext = file.read()

    # Create AES cipher object with key and mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt the ciphertext
    padded_plaintext = cipher.decrypt(ciphertext)

    # Unpad the decrypted plaintext
    plaintext = unpad(padded_plaintext, AES.block_size)

    # Write the decrypted data back to the file
    with open(file_path, 'wb') as file:
        file.write(plaintext)

def encrypt_folder(folder_path, key, mode):
    start_time = time.time()
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if mode == 'encrypt':
                encrypt_file(file_path, key)
                print(f'Encrypted: {file_path}')
            elif mode == 'decrypt':
                decrypt_file(file_path, key)
                print(f'Decrypted: {file_path}')
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Execution Time: {execution_time:.3f} seconds ({execution_time * 1000:.3f} milliseconds)")

# Prompt the user for inputs
while True:
    try:
        password = input("Enter the password: ")
        salt = input("Enter the salt: ")
        length = int(input("Enter the desired key length in bytes: "))
        n = int(input("Enter the value for 'n': "))
        r = int(input("Enter the value for 'r': "))
        p = int(input("Enter the value for 'p': "))
        break
    except ValueError:
        print("Invalid input. Please try again.")

# Call the hkdf_scrypt function with user inputs
derived_key = hkdf_scrypt(password, salt, length, n, r, p)

# Prompt the user to input the folder path
while True:
    folder_path = input("Enter the folder path: ")
    if os.path.isdir(folder_path):
        break
    else:
        print("Invalid folder path. Please try again.")

# Prompt the user to select the mode: 'encrypt' or 'decrypt'
while True:
    mode = input("Enter the mode ('encrypt' or 'decrypt'): ")
    if mode in ['encrypt', 'decrypt']:
        break
    else:
        print("Invalid mode. Please try again.")

# Encrypt or decrypt the files within the folder using AES-256
encrypt_folder(folder_path, derived_key, mode)
