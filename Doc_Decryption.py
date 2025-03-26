import json
from Crypto.Cipher import AES
from .SSS import get_secret  # Importing Shamir's Secret Sharing reconstruction function

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

# Dictionary for changeable decryption algorithms
decryption_algorithms = {
    "AES-CTR": {
        "decrypt": aes_decrypt
    }
}

def decrypt_doc(encrypted_filename, secret_shares, algo="AES-CTR"):
    
    """
    Decrypts a document using the specified algorithm and secret sharing.

    :param encrypted_filename: The encrypted file to decrypt.
    :param secret_shares: JSON string containing secret shares.
    :param algo: The decryption algorithm to use (default: "AES-CTR").
    :return: The decrypted file name.
    """
    
    if algo not in decryption_algorithms:
        raise ValueError(f"Unsupported decryption algorithm: {algo}")

    # Parse JSON and validate structure
    secret_shares_dict = json.loads(secret_shares)
    required_keys = ["owner", "people", "k", "o", "l"]
    if not all(key in secret_shares_dict for key in required_keys):
        raise ValueError("Invalid secret_shares format!")

    # Reconstruct bitstring
    reconstructed_bitstring = get_secret(secret_shares_dict)

    # Convert to bytes and validate length (32 + 8 = 40 bytes)
    key_iv_bytes = bitstring_to_bytes(reconstructed_bitstring)
    if len(key_iv_bytes) != 40:
        raise ValueError("Invalid key/IV length!")
    
    # Extract key and IV
    key = key_iv_bytes[:32]  # First 32 bytes = AES key
    iv = key_iv_bytes[32:40] # Remaining 8 bytes = IV

    # Read encrypted data
    with open(encrypted_filename, 'rb') as f:
        ciphertext = f.read()

    # Decrypt
    decrypt_func = decryption_algorithms[algo]["decrypt"]
    plaintext = decrypt_func(ciphertext, key, iv)

    # Save decrypted file
    decrypted_filename = encrypted_filename.replace(".enc", "_decrypted")
    with open(decrypted_filename, 'wb') as f:
        f.write(plaintext)

    return decrypted_filename