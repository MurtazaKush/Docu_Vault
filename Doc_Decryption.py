import json
import os
from Crypto.Cipher import AES

def decrypt_file(encrypted_file, metadata_file):
    with open(metadata_file, 'r') as f:
        metadata = json.load(f)

    key = bytes.fromhex(metadata["key"])
    iv = bytes.fromhex(metadata["iv"])
    original_filename = metadata["original_filename"]

    with open(encrypted_file, 'rb') as f:
        encrypted_data = f.read()

    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)  # Using full IV as nonce
    decrypted_data = cipher.decrypt(encrypted_data)

    decrypted_file = f"decrypted_{original_filename}"
    with open(decrypted_file, 'wb') as f:
        f.write(decrypted_data)

    print(f"Decryption complete! File saved as: {decrypted_file}")

decrypt_file("ax_encrypted.bin", "ax_encrypted.bin_meta.json")