import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def aes_generate_key():
    return get_random_bytes(32)  # AES-256 key

def aes_encrypt(plaintext, key):
    iv = get_random_bytes(8)  # AES-CTR nonce
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, iv

def bytes_to_bitstring(byte_data):
    """Convert bytes to a bitstring representation ('0' and '1')."""
    return ''.join(f"{byte:08b}" for byte in byte_data)

def encrypt_doc(input_doc, algorithm="AES"):
    """
    Encrypts a document and stores the encrypted file.
    """
    key = aes_generate_key()

    with open(input_doc, 'rb') as f:
        plaintext = f.read()

    ciphertext, iv = aes_encrypt(plaintext, key)

    # Save the encrypted document
    encrypted_filename = f"{input_doc}.enc"
    with open(encrypted_filename, 'wb') as f:
        f.write(ciphertext)

    # Convert key + IV to bitstring (for later secret sharing)
    key_iv_bitstring = bytes_to_bitstring(key + iv)

    return encrypted_filename, key_iv_bitstring  # Return encrypted file name + key_iv bitstring

# The decryption function should use get_secret() from SSS to reconstruct the key+IV and decrypt.