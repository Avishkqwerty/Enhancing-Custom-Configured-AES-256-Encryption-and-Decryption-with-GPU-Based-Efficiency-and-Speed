import hashlib
import hmac
import math
import scrypt

def entropy(data):
    # Calculate the entropy of the data using Shannon's entropy formula
    if not data:
        return 0.0

    prob = [float(data.count(c)) / len(data) for c in dict.fromkeys(list(data))]
    entropy = - sum([p * math.log2(p) for p in prob])
    return entropy

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
password = "USERpPASSWORD12323434_"
salt = "2a8f9e0d7b3c56a1e54f8c37d9b0e267"
length = 32
n = 2
r = 16
p = 1

# Call the custom_key_derivative function with the provided inputs
custom_derived_key = custom_key_derivative(password, salt, length, n, r, p)
print("Custom Derived Key:", custom_derived_key.hex())

# Generate the derived keys using other existing KDFs
existing_derived_key1 = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, length)
existing_derived_key2 = scrypt.hash(password, salt, N=16384, r=8, p=1, buflen=length)

# Calculate the entropy of the derived keys
custom_entropy = entropy(custom_derived_key)
existing_entropy1 = entropy(existing_derived_key1)
existing_entropy2 = entropy(existing_derived_key2)

print(f"Custom Derived Key Entropy: {custom_entropy}")
print(f"Existing Derived Key 1 Entropy: {existing_entropy1}")
print(f"Existing Derived Key 2 Entropy: {existing_entropy2}")
