import requests
import click
import json
import os
import base64
from rich.console import Console
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from hash_rsa import generate_hash, hash_to_rsa_key
from Doc_encryption import encrypt_doc
from SSS import spilt_secret

BASE_URL = "http://127.0.0.1:8000"
console = Console()

class SecureVaultClient:
    def __init__(self):
        self.session = requests.Session()
        
    def signup(self, username: str, password: str):
        """Signup a new user."""
        passhash = generate_hash(password)
        private_key, public_key = hash_to_rsa_key(username, password)
        pb_key = public_key.export_key().decode()

        response = self.session.post(
            f"{BASE_URL}/signup/",
            json={"username": username, "passhash": passhash, "pb_key": pb_key}
        )
        if response.ok:
            console.print("[green]Signup successful![/green]")
            return True
        console.print(f"[red]Signup failed! {response.text}[/red]")
        return False

    def login(self, username: str, password: str) -> bool:
        """Login a user."""
        passhash = generate_hash(password)
        response = self.session.post(
            f"{BASE_URL}/login/",
            json={"username": username, "passhash": passhash}
        )
        if response.ok and response.json():
            console.print("[green]Login successful![/green]")
            return True
        console.print(f"[red]Login failed! {response.text}[/red]")
        return False

    def get_pbkeys(self, usernames: list[str]) -> dict:
        """Get public keys for specified users."""
        response = self.session.post(f"{BASE_URL}/pbkey/", json=usernames)
        if response.ok:
            return {user['username']: user['pb_key'] for user in response.json()}
        console.print(f"[red]Failed to get public keys: {response.text}[/red]")
        return {}

    def change_password(self, username: str, old_password: str, new_password: str):
        """Change user password and update secrets."""
        old_passhash = generate_hash(old_password)
        new_passhash = generate_hash(new_password)
        private_key, public_key = hash_to_rsa_key(username, new_password)
        new_pb_key = public_key.export_key().decode()

        # Get existing secrets
        response = self.session.post(
            f"{BASE_URL}/change_pass_get/",
            json={"username": username, "passhash": old_passhash}
        )
        if not response.ok or not response.json().get("valid"):
            console.print("[red]Failed to get existing secrets[/red]")
            return False

        # Update secrets with new password
        response = self.session.post(
            f"{BASE_URL}/change_pass/",
            json={
                "username": username,
                "oldpasshash": old_passhash,
                "newpasshash": new_passhash,
                "updated_secret": response.json(),
                "newpb": new_pb_key
            }
        )
        if response.ok:
            console.print("[green]Password changed successfully![/green]")
            return True
        console.print(f"[red]Password change failed! {response.text}[/red]")
        return False

    def upload_document(self, username: str, password: str, file_path: str,
                      owners: list[str], people: list[str], k: int, description: str):
        """Upload a document with secret sharing."""
        if not self.login(username, password):
            return False

        # Encrypt document
        enc_file, key_iv_bits = encrypt_doc(file_path)
        l_length = len(key_iv_bits)

        # Split secret
        n = len(owners) + len(people)
        sss_shares = spilt_secret(key_iv_bits, len(owners), k, n)

        # Get all public keys
        pb_keys = self.get_pbkeys(owners + people)
        if len(pb_keys) != len(owners + people):
            console.print("[red]Missing public keys for some users[/red]")
            return False

        # Encrypt shares
        def encrypt_share(share: str, pb_key: str) -> str:
            key = RSA.import_key(pb_key)
            cipher = PKCS1_OAEP.new(key)
            return base64.b64encode(cipher.encrypt(share.encode())).decode()

        # Prepare owner secrets
        owner_secrets = []
        for i, owner in enumerate(owners):
            encrypted = encrypt_share(sss_shares['owner'][i], pb_keys[owner])
            owner_secrets.append({"username": owner, "user_secret": encrypted})

        # Prepare people secrets
        people_secrets = []
        for i, person in enumerate(people):
            encrypted = encrypt_share(sss_shares['people'][i], pb_keys[person])
            people_secrets.append({"username": person, "user_secret": encrypted})

        # Prepare payload
        payload = {
            "username": username,
            "passhash": generate_hash(password),
            "list_owners": owner_secrets,
            "list_people": people_secrets,
            "k": k,
            "filename": os.path.basename(file_path),
            "description": description,
            "l": l_length
        }

        # Send request with file
        with open(enc_file, "rb") as f:
            response = self.session.post(
                f"{BASE_URL}/add_doc/",
                data={"up_doc": json.dumps(payload)},
                files={"file": f}
            )

        if response.ok:
            console.print("[green]Document uploaded successfully![/green]")
            return True
        console.print(f"[red]Document upload failed: {response.text}[/red]")
        return False

@click.group()
def cli():
    """Secure Document Vault CLI."""
    pass

@cli.command()
@click.argument("username")
@click.argument("password")
def signup(username, password):
    """Register new user"""
    SecureVaultClient().signup(username, password)

@cli.command()
@click.argument("username")
@click.argument("password")
def login(username, password):
    """User login"""
    SecureVaultClient().login(username, password)

@cli.command()
@click.argument("username")
@click.argument("old_password")
@click.argument("new_password")
def change_password(username, old_password, new_password):
    """Change password"""
    SecureVaultClient().change_password(username, old_password, new_password)

@cli.command()
@click.argument("username")
@click.argument("password")
@click.argument("file_path")
@click.option("--owners", "-o", multiple=True, required=True)
@click.option("--people", "-p", multiple=True, required=True)
@click.option("--k", type=int, required=True)
@click.option("--description", "-d", required=True)
def upload(username, password, file_path, owners, people, k, description):
    """Upload document"""
    client = SecureVaultClient()
    client.upload_document(
        username=username,
        password=password,
        file_path=file_path,
        owners=list(owners),
        people=list(people),
        k=k,
        description=description
    )

if __name__ == "__main__":
    cli()