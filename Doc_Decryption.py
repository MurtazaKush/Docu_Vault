import json
from Crypto.Cipher import AES
from SSS import get_secret  # Importing SSS reconstruction function

def bitstring_to_bytes(bitstring):
    """Convert a bitstring ('0' and '1') back to bytes."""
    byte_array = bytearray()
    for i in range(0, len(bitstring), 8):
        byte_array.append(int(bitstring[i:i+8], 2))
    return bytes(byte_array)

def aes_decrypt(ciphertext, key, iv):
    """Decrypts AES-CTR encrypted data."""
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    return cipher.decrypt(ciphertext)

def decrypt_doc(encrypted_filename, reconstructed_bitstring):
    """
    Decrypts a document using a reconstructed bitstring.
    """
    # Convert bitstring back to bytes
    key_iv_bytes = bitstring_to_bytes(reconstructed_bitstring)
    
    # Extract AES key and IV
    key = key_iv_bytes[:32]  # First 32 bytes = AES key
    iv = key_iv_bytes[32:]   # Remaining 8 bytes = IV

    # Read encrypted data
    with open(encrypted_filename, 'rb') as f:
        ciphertext = f.read()

    # Decrypt
    plaintext = aes_decrypt(ciphertext, key, iv)

    # Save decrypted file
    decrypted_filename = encrypted_filename.replace(".enc", "_decrypted")
    with open(decrypted_filename, 'wb') as f:
        f.write(plaintext)

    print(f"Decryption complete! File saved as: {decrypted_filename}")
    return decrypted_filename
