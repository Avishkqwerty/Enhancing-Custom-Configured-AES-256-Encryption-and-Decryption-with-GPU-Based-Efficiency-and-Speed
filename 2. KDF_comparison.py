import hashlib
import hmac
import secrets
import scrypt

def compare_key_security(derived_key1, derived_key2):
    if derived_key1 is None or derived_key2 is None:
        return "One or both derived keys are None"

    # Measure the strength of the derived keys
    strength1 = measure_key_strength(derived_key1)
    strength2 = measure_key_strength(derived_key2)

    # Compare the strengths and determine which key is more secure
    if strength1 > strength2:
        return "Custom KDF is more secure"
    elif strength1 < strength2:
        return "Existing KDF is more secure"
    else:
        return "Both derived keys have equal security"

def measure_key_strength(key):
    if key is None:
        return 0.0

    # Measure the strength of the key using a suitable metric
    # For example, you can calculate the entropy or perform statistical tests

    # Here's an example of measuring key strength by counting the number of zero bits
    zero_bits = bin(int.from_bytes(key, 'big')).count('0')
    strength = zero_bits / len(key)

    return strength

# Define your custom key derivative function
def custom_key_derivative(password, salt, length, n, r, p):
    prk = hmac.new(salt.encode(), password.encode(), hashlib.sha256).digest()

    info = b'Scrypt key derivation'
    t = b''
    okm = b''
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([len(t) + 1]), hashlib.sha256).digest()
        okm += scrypt.hash(t, salt=salt.encode(), N=n, r=r, p=p, buflen=length)

    return okm[:length]

# Set the input values
password = "password123"
salt = "somesalt"
length = 32
n = 2
r = 16
p = 1

# Call the custom_key_derivative function with the provided inputs
custom_derived_key = custom_key_derivative(password, salt, length, n, r, p)
print("Custom Derived Key:", custom_derived_key.hex())

# Prompt the user for inputs
# password = input("Enter the password: ")
# salt = input("Enter the salt: ")
# length = int(input("Enter the desired key length in bytes: "))

# Generate the derived keys using other existing KDFs
existing_derived_key1 = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, length)
existing_derived_key2 = scrypt.hash(password, salt, N=16384, r=8, p=1, buflen=length)

# Compare the security of the derived keys
result = compare_key_security(custom_derived_key, existing_derived_key1)
print(result)

result = compare_key_security(custom_derived_key, existing_derived_key2)
print(result)
