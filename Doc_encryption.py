import os
import json
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes

def aes_generate_key():
    return get_random_bytes(32)  # AES-256 key

def aes_encrypt(plaintext, key):
    iv = get_random_bytes(8)  # AES-CTR nonce
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, iv

def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    return cipher.decrypt(ciphertext)

ENCRYPTION_ALGORITHMS = {
    "AES": {
        "generate_key": aes_generate_key,
        "encrypt": aes_encrypt,
        "decrypt": aes_decrypt,
    } 
    #"DES": {
    #    "generate_key": des_generate_key,
    #    "encrypt": des_encrypt,
    #    "decrypt": des_decrypt,
    #}
}

def encrypt_doc(input_doc, output, algorithm="AES"):
    """
    Encrypts a document using the specified algorithm (AES or DES).
    """
    algo = ENCRYPTION_ALGORITHMS[algorithm]
    key = algo["generate_key"]()

    with open(input_doc, 'rb') as f:
        plaintext = f.read()

    ciphertext, iv = algo["encrypt"](plaintext, key)

    with open(output, 'wb') as f:
        f.write(ciphertext)

    encryption_metadata = {
        "key": key.hex(),
        "iv": iv.hex(),
        "original_filename": os.path.basename(input_doc)
    }

    with open(output + "_meta.json", 'w') as f:
        json.dump(encryption_metadata, f)

    print(f"Encryption complete! Encrypted file saved as: {output}")
    print(f"Metadata saved as: {output}_meta.json")


alg = "AES"
encrypt_doc("B.Tech CSE III B- L2.pdf", "ax_encrypted.bin", alg)