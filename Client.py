# Client.py (Fully Aligned Version)
import requests
import click
import json
import os
import base64
import time
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from hash_rsa import generate_hash, hash_to_rsa_key
from Doc_encryption import encrypt_doc
from SSS import spilt_secret
from Doc_Decryption import decrypt_doc

BASE_URL = "http://127.0.0.1:8000"
console = Console()

class SecureVaultClient:
    def __init__(self):
        self.session = requests.Session()
        self.current_user = None

    # --- Authentication Flow ---
    def login(self, username: str, password: str) -> bool:
        """Handle login with hash_rsa integration"""
        try:
            passhash = generate_hash(password)
            response = self.session.post(
                f"{BASE_URL}/login/",
                json={"username": username, "passhash": passhash}
            )
            if response.ok and response.json():
                self.current_user = (username, password)
                return True
            return False
        except Exception as e:
            console.print(f"[red]Login error: {str(e)}[/red]")
            return False

    def signup(self, username: str, password: str) -> bool:
        """Handle signup with RSA key generation"""
        try:
            passhash = generate_hash(password)
            private_key, public_key = hash_to_rsa_key(username, password)
            
            response = self.session.post(
                f"{BASE_URL}/signup/",
                json={
                    "username": username,
                    "passhash": passhash,
                    "pb_key": public_key.export_key().decode()
                }
            )
            return response.ok
        except Exception as e:
            console.print(f"[red]Signup error: {str(e)}[/red]")
            return False

    # --- Document Management ---
    def upload_document(self, file_path: str, owners: list, people: list, k: int, description: str) -> bool:
        """Full document upload workflow"""
        try:
            # Validate no overlap
            if set(owners) & set(people):
                console.print("[red]Cannot have overlapping owners and people![/red]")
                return False

            # Encrypt document
            enc_file, key_iv_bits = encrypt_doc(file_path)
            
            # Split secret using SSS
            sss_shares = spilt_secret(key_iv_bits, len(owners), k, len(owners)+len(people))

            # Get public keys
            pb_keys = self.get_pbkeys(owners + people)
            if len(pb_keys) != len(owners + people):
                console.print("[red]Missing public keys for some users![/red]")
                return False

            # Encrypt shares
            def _encrypt_share(share: str, username: str) -> str:
                cipher = PKCS1_OAEP.new(RSA.import_key(pb_keys[username]))
                return base64.b64encode(cipher.encrypt(share.encode())).decode()

            owner_secrets = [
                {"username": o, "user_secret": _encrypt_share(sss_shares['owner'][i], o)}
                for i, o in enumerate(owners)
            ]
            people_secrets = [
                {"username": p, "user_secret": _encrypt_share(sss_shares['people'][i], p)}
                for i, p in enumerate(people)
            ]

            # Prepare payload
            payload = {
                "username": self.current_user[0],
                "passhash": generate_hash(self.current_user[1]),
                "list_owners": owner_secrets,
                "list_people": people_secrets,
                "k": k,
                "filename": os.path.basename(file_path),
                "description": description,
                "l": len(key_iv_bits)
            }

            # Send to server
            with open(enc_file, "rb") as f:
                response = self.session.post(
                    f"{BASE_URL}/add_doc/",
                    data={"up_doc": json.dumps(payload)},
                    files={"file": f}
                )
            return response.ok
        except Exception as e:
            console.print(f"[red]Upload failed: {str(e)}[/red]")
            return False

    # --- Request Workflow ---
    def create_request(self, doc_id: int, req_type: str, valid_hours: int) -> bool:
        """Create access request with server validation"""
        try:
            response = self.session.post(
                f"{BASE_URL}/create_request/",
                json={
                    "user_id": self.current_user[0],
                    "passhash": generate_hash(self.current_user[1]),
                    "doc_id": doc_id,
                    "req_type": req_type.upper(),
                    "valid_time": valid_hours
                }
            )
            return response.ok
        except Exception as e:
            console.print(f"[red]Request creation failed: {str(e)}[/red]")
            return False

    def sign_request(self, req_id: int) -> bool:
        """Complete approval workflow with re-encryption"""
        try:
            # Get requester's public key
            req_info = self.session.post(
                f"{BASE_URL}/my_requests/",
                json={"username": self.current_user[0], "passhash": generate_hash(self.current_user[1])}
            ).json()
            requester_id = next((r['user_id'] for r in req_info if r['req_id'] == req_id), None)
            pbkey = self.get_pbkeys([requester_id]).get(requester_id)

            # Get and decrypt secret
            secret_resp = self.session.post(
                f"{BASE_URL}/get_my_secret/",
                json={
                    "username": self.current_user[0],
                    "passhash": generate_hash(self.current_user[1]),
                    "doc_id": next(r['doc_id'] for r in req_info if r['req_id'] == req_id)
                }
            )
            private_key, _ = hash_to_rsa_key(*self.current_user)
            decrypted = PKCS1_OAEP.new(private_key).decrypt(
                base64.b64decode(secret_resp.text)
            ).decode()

            # Re-encrypt and submit
            reencrypted = base64.b64encode(
                PKCS1_OAEP.new(RSA.import_key(pbkey)).encrypt(decrypted.encode())
            ).decode()

            response = self.session.post(
                f"{BASE_URL}/sign_req/",
                json={
                    "username": self.current_user[0],
                    "passhash": generate_hash(self.current_user[1]),
                    "req_id": req_id,
                    "encrypted_secret": reencrypted
                }
            )
            return response.ok
        except Exception as e:
            console.print(f"[red]Approval failed: {str(e)}[/red]")
            return False

    # --- Helper Methods ---
    def get_pbkeys(self, usernames: list) -> dict:
        """Batch fetch public keys from server"""
        try:
            response = self.session.post(f"{BASE_URL}/pbkey/", json=usernames)
            return {u['username']: u['pb_key'] for u in response.json()}
        except:
            return {}

    # --- UI Components ---
    def show_documents(self):
        """Display documents with access type"""
        try:
            response = self.session.post(
                f"{BASE_URL}/my_docs/",
                json={"username": self.current_user[0], "passhash": generate_hash(self.current_user[1])}
            )
            docs = response.json()
            
            table = Table(title="Your Documents", show_header=True)
            table.add_column("ID", style="cyan")
            table.add_column("Filename")
            table.add_column("Access Type")
            
            for doc in docs.get('owner', []):
                table.add_row(str(doc['id']), doc['filename'], "[green]Owner[/green]")
            for doc in docs.get('people', []):
                table.add_row(str(doc['id']), doc['filename'], "[yellow]People[/yellow]")
            
            console.print(table)
        except Exception as e:
            console.print(f"[red]Failed to load documents: {str(e)}[/red]")

# CLI Implementation (Full Version)
@click.group()
@click.pass_context
def cli(ctx):
    """Secure Document Vault CLI"""
    ctx.obj = SecureVaultClient()

@cli.command()
@click.argument("username")
@click.argument("password")
def signup(username, password):
    """Register new user"""
    if SecureVaultClient().signup(username, password):
        console.print(f"[green]Successfully signed up {username}![/green]")
    else:
        console.print("[red]Signup failed![/red]")

@cli.command()
@click.argument("username")
@click.argument("password")
@click.pass_obj
def login(client, username, password):
    """User login"""
    if client.login(username, password):
        console.print(f"[green]Logged in as {username}[/green]")
    else:
        console.print("[red]Login failed![/red]")

@cli.command()
@click.argument("file_path")
@click.option("--owners", "-o", multiple=True, required=True, help="List of owners")
@click.option("--people", "-p", multiple=True, required=True, help="List of people")
@click.option("--k", type=int, required=True, help="Threshold for people")
@click.option("--description", "-d", required=True, help="Document description")
@click.pass_obj
def upload(client, file_path, owners, people, k, description):
    """Upload a document"""
    if client.upload_document(file_path, list(owners), list(people), k, description):
        console.print("[green]Document uploaded successfully![/green]")
    else:
        console.print("[red]Document upload failed![/red]")

@cli.command()
@click.pass_obj
def list_docs(client):
    """List accessible documents"""
    client.show_documents()

@cli.command()
@click.option("--doc-id", type=int, required=True, help="Document ID to request")
@click.option("--type", "-t", type=click.Choice(['read', 'write'], case_sensitive=False), 
             default='read', help="Request type (read/write)")
@click.option("--hours", "-h", type=int, default=24, help="Validity hours")
@click.pass_obj
def request(client, doc_id, type, hours):
    """Create access request"""
    if client.create_request(doc_id, type, hours):
        console.print("[green]Request created successfully![/green]")
    else:
        console.print("[red]Request creation failed![/red]")

@cli.command()
@click.pass_obj
def pending(client):
    """Show pending approvals"""
    try:
        response = client.session.post(
            f"{BASE_URL}/other_requests/",
            json={"username": client.current_user[0], 
                 "passhash": generate_hash(client.current_user[1])}
        )
        requests = response.json()
        
        table = Table(title="Pending Approvals", show_header=True)
        table.add_column("ID", style="cyan")
        table.add_column("Document")
        table.add_column("Requester")
        table.add_column("Type")
        
        for req in requests:
            req_type = "[yellow]READ[/yellow]" if req['req_type'] == "r" else "[red]WRITE[/red]"
            table.add_row(
                str(req['req_id']),
                req['filename'],
                req['user_id'],
                req_type
            )
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error loading requests: {str(e)}[/red]")

@cli.command()
@click.option("--req-id", type=int, required=True, help="Request ID to approve")
@click.pass_obj
def approve(client, req_id):
    """Approve a request"""
    if client.sign_request(req_id):
        console.print("[green]Approval successful![/green]")
    else:
        console.print("[red]Approval failed![/red]")

@cli.command()
@click.option("--doc-id", type=int, required=True, help="Document ID to download")
@click.pass_obj
def download(client, doc_id):
    """Download decrypted document"""
    if client.download_document(doc_id):
        console.print("[green]Document downloaded successfully![/green]")
    else:
        console.print("[red]Document download failed![/red]")

if __name__ == "__main__":
    cli()