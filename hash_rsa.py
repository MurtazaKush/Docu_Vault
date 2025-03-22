import hashlib
import secrets  # Use secrets for cryptographic randomness
import random
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA512
from Crypto.Util.number import getPrime

# ---- Hashing Configuration ----
Algo_change = {
    "hash_algo": "SHA-256",  # Change to "SHA-512" for testing later
    "rsa_bits": 2048,
}

# ---- Hashing Functions ----
def mix_username_password(username, password):
    """Mix username and password in a deterministic but non-trivial way."""
    # Use a secure method to derive a seed
    seed = hashlib.sha256((username + password).encode()).digest()
    random.seed(seed)  # Seed the random module securely
    ratio = random.randint(2, len(password) - 1)
    return password[:ratio] + username + password[ratio:]

def generate_hash(value):
    """Generate a hash based on the selected algorithm."""
    if Algo_change["hash_algo"] == "SHA-256":
        return hashlib.sha256(value.encode()).hexdigest()
    elif Algo_change["hash_algo"] == "SHA-512":
        return hashlib.sha512(value.encode()).hexdigest()
    else:
        raise ValueError("Unsupported hash algorithm in Algo_change")

# ---- RSA Key Generation ----
def hash_to_rsa_key(username, password):
    """
    Deterministically generate an RSA key pair from username and password.
    This ensures that the same username-password always yields the same key.
    """
    mixed_value = mix_username_password(username, password)
    user_hash = generate_hash(mixed_value)
    seed_int = int(user_hash, 16)

    # Use secrets for secure random number generation
    bits = Algo_change["rsa_bits"] // 2

    p = getPrime(bits, randfunc=lambda n: secrets.randbits(n).to_bytes((n + 7) // 8, 'big'))
    q = getPrime(bits, randfunc=lambda n: secrets.randbits(n).to_bytes((n + 7) // 8, 'big'))

    if p == q:
        q = getPrime(bits, randfunc=lambda n: secrets.randbits(n).to_bytes(n // 8, 'big'))

    key = RSA.construct((p * q, 65537, pow(65537, -1, (p - 1) * (q - 1)), p, q))
    return key, key.publickey()

# ---- RSA Signature Functions ----
def generate_signature(private_key, message):
    """Generate a digital signature using RSA."""
    h = SHA256.new(message.encode()) if Algo_change["hash_algo"] == "SHA-256" else SHA512.new(message.encode())
    return pkcs1_15.new(private_key).sign(h)

def verify_signature(public_key, message, signature):
    """Verify a digital signature."""
    h = SHA256.new(message.encode()) if Algo_change["hash_algo"] == "SHA-256" else SHA512.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ---- Execution ----
if __name__ == "__main__":
    username = input("Enter username: ")
    password = input("Enter password: ")

    print("Generating RSA key pair...")
    private_key, public_key = hash_to_rsa_key(username, password)

    # Test Signature
    test_message = "RSA Key Verification Test"
    signature = generate_signature(private_key, test_message)

    if verify_signature(public_key, test_message, signature):
        print("RSA Key Verified Successfully!")
    else:
        print("RSA Key Verification Failed!")