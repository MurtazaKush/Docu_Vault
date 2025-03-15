import hashlib
import random
import json
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA512
from Crypto.Util.number import getPrime

RSA_KEY_FILE = "rsa_keys.json"

Algo_change = {
    "hash_algo": "SHA-256", # 512 later we will use for testing purposes
    "rsa_bits": 2048,        
}

def load_stored_keys():
    """Loading stored RSA keys from JSON file."""
    if os.path.exists(RSA_KEY_FILE):
        with open(RSA_KEY_FILE, "r") as f:
            return json.load(f)
    return {}

def save_stored_keys(data):
    """Save RSA keys to JSON file."""
    with open(RSA_KEY_FILE, "w") as f:
        json.dump(data, f, indent=4)

# ---- Hashing Functions ----
def mix_username_password(username, password):
    """Mix username and password in a deterministic but non-trivial way."""
    random.seed(len(username) + len(password)) 
    ratio = random.randint(2, len(password) - 1)
    return password[:ratio] + username + password[ratio:]

def generate_hash(value):
    """Generate a hash based on selected algorithm from Algo_change dictionary."""
    if Algo_change["hash_algo"] == "SHA-256":
        return hashlib.sha256(value.encode()).hexdigest()
    elif Algo_change["hash_algo"] == "SHA-512":
        return hashlib.sha512(value.encode()).hexdigest()
    else:
        raise ValueError("Unsupported hash algorithm in Algo_change")

# ---- RSA Key Generation ----
def hash_to_rsa_key(username, password):
    mixed_value = mix_username_password(username, password)
    user_hash = generate_hash(mixed_value)
    seed_int = int(user_hash, 16)

    random.seed(seed_int)
    bits = Algo_change["rsa_bits"] // 2

    p = getPrime(bits, randfunc=lambda n: random.getrandbits(n).to_bytes((n + 7) // 8, 'big'))
    q = getPrime(bits, randfunc=lambda n: random.getrandbits(n).to_bytes((n + 7) // 8, 'big'))


    if p == q:  
        q = getPrime(bits, randfunc=lambda n: random.getrandbits(n).to_bytes(n // 8, 'big'))

    key = RSA.construct((p * q, 65537, pow(65537, -1, (p - 1) * (q - 1)), p, q))
    return key, key.publickey()

# ---- RSA Signature Functions ----
def generate_signature(private_key, message):
    """Generate a signature using RSA."""
    h = SHA256.new(message.encode()) if Algo_change["hash_algo"] == "SHA-256" else SHA512.new(message.encode())
    return pkcs1_15.new(private_key).sign(h)

def verify_signature(public_key, message, signature):
    """Verify the signature."""
    h = SHA256.new(message.encode()) if Algo_change["hash_algo"] == "SHA-256" else SHA512.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ---- Loading Stored Keys ----
stored_keys = load_stored_keys()

# ---- Execution ----
if __name__ == "__main__":
    username = input("Enter username: ")
    password = input("Enter password: ")

    hashed_password = generate_hash(password)

    if username in stored_keys:
        stored_password_hash = stored_keys[username]["password_hash"]
        
        if hashed_password == stored_password_hash:
            print("Password Verified! Loading existing RSA key...")
            private_key = RSA.import_key(stored_keys[username]["private_key"])
            public_key = RSA.import_key(stored_keys[username]["public_key"])
        else:
            print("Incorrect password! RSA Key Verification Failed.")
            exit(1)  # To stop execution for incorrect passwords
    else:
        print("New user detected! Generating RSA Key Pair...")
        private_key, public_key = hash_to_rsa_key(username, password)
        
        stored_keys[username] = {
            "password_hash": hashed_password,
            "private_key": private_key.export_key().decode(),
            "public_key": public_key.export_key().decode()
        }
        save_stored_keys(stored_keys)

    # Test Signature
    test_message = "RSA Key Verification Test"
    signature = generate_signature(private_key, test_message)

    if verify_signature(public_key, test_message, signature):
        print("RSA Key Verified Successfully!")
    else:
        print("RSA Key Verification Failed!")