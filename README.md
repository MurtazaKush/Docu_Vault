# Docu_Vault

# Secure Document Encryption and Decryption System

## Overview

This project provides a secure system for encrypting, decrypting, hashing, and sharing documents using cryptographic techniques. It supports RSA, AES, and DES encryption, secure hashing, secret sharing, and a client-server model for secure communication.

## Features

- **Document Encryption & Decryption** (`Doc_encryption.py`, `Doc_Decryption.py`): Uses RSA, AES, and DES encryption algorithms.
- **Secure Hashing** (`hash_rsa.py`): Implements hashing using SHA-256.
- **Secret Sharing** (`SSS.py`): Implements Shamir’s Secret Sharing to distribute a secret among multiple participants.
- **Database Management** (`database.py`, `models.py`): Manages user authentication and document storage.
- **Client-Server Communication** (`server.py`, `newClient.py`): Facilitates secure message exchange between client and server.

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/MurtazaKush/Docu_Vault.git
   cd Docu_Vault
   ```
2. Create virtual environment in python
   ```sh
   python -m venv venv
   ```
4. Install dependencies:
   ```sh
   pip install -r req.txt
   ```
5. Start the server:
   Run from parent of git directory after activating virtual environment
   ```sh
   uvicorn Docu_Vault.server:app
   ```
6. Run the client:
   Run from parent of git directory after activating virtual environment
   ```sh
   python -m Docu_Vault.newClient
   ```

## License
This project is open-source under the MIT License.
```

