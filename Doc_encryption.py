from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def aes_generate_key():
    """Generate a 256-bit AES key."""
    return get_random_bytes(32)  # 32 bytes = 256 bits

def aes_encrypt(plaintext, key):
    """Encrypt plaintext using AES in CTR mode."""
    iv = get_random_bytes(8)  # 8-byte nonce for AES-CTR
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, iv

def bytes_to_bitstring(byte_data):
    """Convert bytes to a bitstring representation ('0' and '1')."""
    return ''.join(f"{byte:08b}" for byte in byte_data)

# Dictionary for changeable encryption algorithms
encryption_algorithms = {
    "AES-CTR": {
        "generate_key": aes_generate_key,
        "encrypt": aes_encrypt
    }
}

def encrypt_doc(input_doc, algo="AES-CTR"):
    """
    Encrypts a document using the specified algorithm.
    
    :param input_doc: Path to the document to encrypt.
    :param algo: Encryption algorithm to use (default: "AES-CTR").
    :return: Tuple (encrypted_filename, key_iv_bitstring).
    """
    if algo not in encryption_algorithms:
        raise ValueError(f"Unsupported encryption algorithm: {algo}")

    # Fetch encryption functions
    key_gen = encryption_algorithms[algo]["generate_key"]
    encrypt_func = encryption_algorithms[algo]["encrypt"]

    # Generate key and encrypt
    key = key_gen()
    with open(input_doc, 'rb') as f:
        plaintext = f.read()

    ciphertext, iv = encrypt_func(plaintext, key)

    # Save the encrypted document
    encrypted_filename = f"{input_doc}.enc"
    with open(encrypted_filename, 'wb') as f:
        f.write(ciphertext)

    # Concatenate key and IV in binary format
    key_iv_concat = key + iv
    key_iv_bitstring = bytes_to_bitstring(key_iv_concat)

    return encrypted_filename, key_iv_bitstring
