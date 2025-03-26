import hashlib
import random
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime

# ---- Hashing Configuration ----
Algo_change = {
    "hash_algo": "SHA-256",
    "rsa_bits": 4096,  # RSA Key Size
}

# ---- Hashing Functions ----
def mix_username_password(username, password):
    """Mix username and password deterministically."""
    seed = hashlib.sha256((username + password).encode()).digest()
    seed_int = int.from_bytes(seed, "big")
    random.seed(seed_int)  # Ensures the same ratio every time
    
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

# ---- Deterministic RSA Key Generation ----
def hash_to_rsa_key(username, password):
    """
    Deterministically generate an RSA key pair from username and password.
    This ensures that the same username-password always yields the same key.
    """
    mixed_value = mix_username_password(username, password)
    user_hash = generate_hash(mixed_value)
    seed_int = int(user_hash, 16)

    # Ensure the same prime numbers are generated every time
    random.seed(seed_int)

    bits = Algo_change["rsa_bits"] // 2

    p = getPrime(bits, randfunc=lambda n: random.getrandbits(n).to_bytes((n + 7) // 8, 'big'))
    q = getPrime(bits, randfunc=lambda n: random.getrandbits(n).to_bytes((n + 7) // 8, 'big'))

    while p == q:
        q = getPrime(bits, randfunc=lambda n: random.getrandbits(n).to_bytes((n + 7) // 8, 'big'))

    key = RSA.construct((p * q, 65537, pow(65537, -1, (p - 1) * (q - 1)), p, q))
    return key, key.publickey()
