import hashlib
import hmac
import scrypt
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

def decrypt_folder(folder_path, key):
    start_time = time.time()
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
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
folder_path_regex = re.compile(r'^[a-zA-Z0-9_./\\-]+$')  # Alphanumeric, underscore, dot, forward slash, backslash, and hyphen

# Prompt the user for inputs
while True:
    try:
        backup_key_path = input("Enter the backup key file path: ")
        if not os.path.isfile(backup_key_path):
            print("Invalid backup key file path.")
            continue

        folder_path = input("Enter the folder path to decrypt: ")
        if not folder_path_regex.match(folder_path):
            print("Invalid folder path. Folder path must be alphanumeric and can contain underscore, dot, forward slash, backslash, and hyphen.")
            continue
        if os.path.isdir(folder_path):
            break
        else:
            print("Invalid folder path. Please try again.")

        break
    except ValueError:
        print("Invalid input. Please try again.")

# Read the backup key from the file
with open(backup_key_path, 'r') as file:
    encoded_key = file.read()

# Decode the backup key from base64
decoded_key = base64.b64decode(encoded_key)

# Decrypt the folder using the backup key
decrypt_folder(folder_path, decoded_key)
