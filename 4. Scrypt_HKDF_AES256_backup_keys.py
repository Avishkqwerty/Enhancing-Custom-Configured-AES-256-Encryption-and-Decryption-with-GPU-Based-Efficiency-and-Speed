import hashlib
import hmac
import scrypt
import secrets
import os
import time
import re
import psutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

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

    # Generate a random IV (Initialization Vector)
    iv = secrets.token_bytes(AES.block_size)

    # Create AES cipher object with key and mode (CBC)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the plaintext to match AES block size
    padded_plaintext = pad(plaintext, AES.block_size)

    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    # Write the IV and encrypted data back to the file
    with open(file_path, 'wb') as file:
        file.write(iv + ciphertext)

def decrypt_file(file_path, key):
    # Read the file contents
    with open(file_path, 'rb') as file:
        ciphertext = file.read()

    # Extract the IV and ciphertext from the file
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]

    # Create AES cipher object with key and mode (CBC)
    cipher = AES.new(key, AES.MODE_CBC, iv)

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

            # Monitor system resources while processing files
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_percent = psutil.virtual_memory().percent
            print(f"CPU Usage: {cpu_percent}% - Memory Usage: {memory_percent}%")

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Execution Time: {execution_time:.3f} seconds ({execution_time * 1000:.3f} milliseconds)")

# Define regular expressions for input validation
password_regex = re.compile(r'^.{8,}$')  # Minimum 8 characters
salt_regex = re.compile(r'^[a-fA-F0-9]{32}$')  # 32 hexadecimal characters
folder_path_regex = re.compile(r'^[a-zA-Z0-9_./\\-]+$')  # Alphanumeric, underscore, dot, forward slash, backslash, and hyphen

# Prompt the user for inputs
while True:
    try:
        password = input("Enter the password: ")
        if not password_regex.match(password):
            print("Invalid password. Password must be at least 8 characters long.")
            continue

        salt = input("Enter the salt: ")
        if not salt_regex.match(salt):
            print("Invalid salt. Salt must be a 32-character hexadecimal string.")
            continue

        length = int(input("Enter the desired key length in bytes: "))
        n = int(input("Enter the value for 'n': "))
        r = int(input("Enter the value for 'r': "))
        p = int(input("Enter the value for 'p': "))
        break
    except ValueError:
        print("Invalid input. Please try again.")

# Prompt the user to input the folder path
while True:
    folder_path = input("Enter the folder path: ")
    if not folder_path_regex.match(folder_path):
        print("Invalid folder path. Folder path must be alphanumeric and can contain underscore, dot, forward slash, backslash, and hyphen.")
        continue
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

# Call the hkdf_scrypt function with user inputs
derived_key = hkdf_scrypt(password, salt, length, n, r, p)

# Encode the derived key using base64
encoded_key = base64.b64encode(derived_key).decode()

if mode == 'encrypt':
    # Store the encoded key in a secure location (e.g., a file or database)
    with open("backup_key.txt", "w") as file:
        file.write(encoded_key)

# Encrypt or decrypt the files within the folder using AES-256
encrypt_folder(folder_path, derived_key, mode)
