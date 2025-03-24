import requests
import click
import json
import os
import base64
from rich.console import Console
from rich.table import Table
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from hash_rsa import generate_hash, hash_to_rsa_key
from Doc_encryption import encrypt_doc
from SSS import spilt_secret, get_secret
from Doc_Decryption import decrypt_doc, bitstring_to_bytes

BASE_URL = "http://127.0.0.1:8000"
console = Console()

class SecureVaultClient:
    def __init__(self):
        self.session = requests.Session()
        self.current_user = None

    # --- Authentication ---
    def login(self, username: str, password: str) -> bool:
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
        try:
            # Validate no overlap between owners and people
            if set(owners) & set(people):
                console.print("[red]Owners and people cannot overlap![/red]")
                return False

            # Encrypt document
            enc_file, key_iv_bits = encrypt_doc(file_path)
            
            # Split secret using Shamir's Secret Sharing
            # WORKAROUND: Align with server's incorrect n calculation (n = len(people))
            sss_shares = spilt_secret(
                secret=key_iv_bits,
                no_of_owners=len(owners),
                k=k,
                n=len(people)  # Match server's flawed logic
            )

            # Get public keys for all participants
            pb_keys = self.get_pbkeys(owners + people)
            if len(pb_keys) != len(owners + people):
                console.print("[red]Missing public keys![/red]")
                return False

            # Encrypt shares for each user
            def _encrypt_share(share: str, username: str) -> dict:
                cipher = PKCS1_OAEP.new(RSA.import_key(pb_keys[username].encode()))
                encrypted_secret = base64.b64encode(cipher.encrypt(share.encode())).decode()
                return {"username": username, "user_secret": encrypted_secret}

            # Prepare owner and people secrets
            owner_secrets = [
                _encrypt_share(sss_shares['owner'][i], owner)
                for i, owner in enumerate(owners)
            ]
            people_secrets = [
                _encrypt_share(sss_shares['people'][i], person)
                for i, person in enumerate(people)
            ]

            # Prepare payload for document upload
            payload = {
                "username": self.current_user[0],
                "passhash": generate_hash(self.current_user[1]),
                "list_owners": owner_secrets,
                "list_people": people_secrets,
                "k": k,
                "filename": os.path.basename(file_path),
                "description": description,
                "l": len(key_iv_bits)  # Length of key+IV in bits
            }

            # Upload encrypted file
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

    def download_document(self, doc_id: int) -> bool:
        try:
            # First fetch document metadata using /my_docs/
            docs_response = self.session.post(
                f"{BASE_URL}/my_docs/",
                json={
                    "username": self.current_user[0],
                    "passhash": generate_hash(self.current_user[1])
                }
            )
            if not docs_response.ok:
                console.print("[red]Metadata fetch failed![/red]")
                return False

            # Find the specific document
            docs_data = docs_response.json()
            target_doc = next(
                (doc for doc in docs_data['owner'] + docs_data['people'] 
                 if doc['id'] == doc_id), None
            )
            if not target_doc:
                console.print("[red]Document not found![/red]")
                return False

            # Get TRUE parameters from document metadata
            k = target_doc['k']
            o = target_doc['o']
            l_param = target_doc['l']

            # Fetch the encrypted file
            file_response = self.session.post(
                f"{BASE_URL}/get_file/",
                json={
                    "username": self.current_user[0],
                    "passhash": generate_hash(self.current_user[1]),
                    "doc_id": str(doc_id)
                },
                stream=True
            )
            
            if not file_response.ok:
                console.print("[red]File fetch failed![/red]")
                return False

            # Save encrypted file
            encrypted_path = f"temp_{doc_id}.enc"
            with open(encrypted_path, "wb") as f:
                for chunk in file_response.iter_content(1024):
                    f.write(chunk)

            # Fetch secrets
            secrets_response = self.session.post(
                f"{BASE_URL}/get_secrets/",
                json={
                    "username": self.current_user[0],
                    "passhash": generate_hash(self.current_user[1]),
                    "req_id": doc_id
                }
            )
            
            if not secrets_response.ok:
                console.print("[red]Secrets fetch failed![/red]")
                return False

            # Process secrets with CORRECT parameters
            shares_data = secrets_response.json()
            sss_shares = {
                "owner": [s["user_secret"] for s in shares_data.get("list_owners", [])],
                "people": [s["user_secret"] for s in shares_data.get("list_people", [])],
                "k": k,  # From document metadata
                "o": o,  # From document metadata
                "l": l_param  # From document metadata
            }

            # Reconstruct secret
            reconstructed = get_secret(sss_shares)
            if not reconstructed:
                console.print("[red]Secret reconstruction failed![/red]")
                return False

            # Extract key and IV
            key_iv_bytes = bitstring_to_bytes(reconstructed)
            key = key_iv_bytes[:32]
            iv = key_iv_bytes[32:40]

            # Decrypt document
            decrypted_file = decrypt_doc(encrypted_path, key, iv)
            console.print(f"[green]Decrypted file: {decrypted_file}[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]Download failed: {str(e)}[/red]")
            return False

    def create_request(self, doc_id: int, req_type: str, valid_hours: int) -> bool:
        try:
            response = self.session.post(
                f"{BASE_URL}/create_request/",
                json={
                    "user_id": self.current_user[0],
                    "passhash": generate_hash(self.current_user[1]),
                    "doc_id": doc_id,
                    "req_type": req_type.upper(),  # Ensure 'r' or 'w'
                    "valid_time": valid_hours
                }
            )
            return response.ok
        except Exception as e:
            console.print(f"[red]Request failed: {str(e)}[/red]")
            return False

    def sign_request(self, req_id: int) -> bool:
        try:
            # First fetch the user's requests to find doc_id
            requests_response = self.session.post(
                f"{BASE_URL}/my_requests/",
                json={
                    "username": self.current_user[0],
                    "passhash": generate_hash(self.current_user[1])
                }
            )
            
            if not requests_response.ok:
                console.print("[red]Failed to fetch requests![/red]")
                return False

            # Find the matching request
            target_request = next(
                (req for req in requests_response.json() 
                 if req['req_id'] == req_id), None
            )
            
            if not target_request:
                console.print("[red]Request not found![/red]")
                return False

            # Get the correct doc_id from the request
            doc_id = target_request['doc_id']

            # Now fetch document details with proper doc_id
            doc_details_resp = self.session.post(
                f"{BASE_URL}/get_o_p/",
                json={
                    "username": self.current_user[0],
                    "passhash": generate_hash(self.current_user[1]),
                    "doc_id": doc_id  # Use actual document ID
                }
            )

            if not doc_details_resp.ok:
                console.print("[red]Document details fetch failed![/red]")
                return False

            # Fetch user's secret for THIS DOCUMENT
            secret_resp = self.session.post(
                f"{BASE_URL}/get_my_secret/",
                json={
                    "username": self.current_user[0],
                    "passhash": generate_hash(self.current_user[1]),
                    "doc_id": doc_id  # Use correct doc_id
                }
            )

            if not secret_resp.ok:
                console.print("[red]Secret fetch failed![/red]")
                return False

            # Decrypt the secret (no need for base64 re-encoding)
            private_key, _ = hash_to_rsa_key(*self.current_user)
            decrypted_secret = PKCS1_OAEP.new(private_key).decrypt(
                base64.b64decode(secret_resp.text)
            ).decode()

            # Submit signature with raw decrypted secret
            response = self.session.post(
                f"{BASE_URL}/sign_req/",
                json={
                    "username": self.current_user[0],
                    "passhash": generate_hash(self.current_user[1]),
                    "req_id": req_id,
                    "encrypted_secret": decrypted_secret  # Send raw secret
                }
            )
            return response.ok
            
        except Exception as e:
            console.print(f"[red]Signing failed: {str(e)}[/red]")
            return False

    # --- Helpers ---
    def get_pbkeys(self, usernames: list) -> dict:
        try:
            response = self.session.post(f"{BASE_URL}/pbkey/", json=usernames)
            return {u['username']: u['pb_key'] for u in response.json()}
        except:
            return {}

    def show_documents(self):
        try:
            response = self.session.post(
                f"{BASE_URL}/my_docs/",
                json={"username": self.current_user[0], "passhash": generate_hash(self.current_user[1])}
            )
            docs = response.json()
            
            table = Table(title="Your Documents")
            table.add_column("ID", style="cyan")
            table.add_column("Filename")
            table.add_column("Access Type")
            
            for doc in docs.get('owner', []):
                table.add_row(str(doc['id']), doc['filename'], "[green]Owner[/green]")
            for doc in docs.get('people', []):
                table.add_row(str(doc['id']), doc['filename'], "[yellow]People[/yellow]")
            
            console.print(table)
        except Exception as e:
            console.print(f"[red]Load failed: {str(e)}[/red]")

# CLI Implementation Remains the Same
@click.group()
@click.pass_context
def cli(ctx):
    ctx.obj = SecureVaultClient()

# Rest of the CLI commands remain unchanged
@cli.command()
@click.argument("username")
@click.argument("password")
def signup(username, password):
    if SecureVaultClient().signup(username, password):
        console.print(f"[green]Signed up {username}![/green]")
    else:
        console.print("[red]Signup failed![/red]")

@cli.command()
@click.argument("username")
@click.argument("password")
@click.pass_obj
def login(client, username, password):
    if client.login(username, password):
        console.print(f"[green]Logged in as {username}[/green]")
    else:
        console.print("[red]Login failed![/red]")
@cli.command()
@click.argument("file_path")
@click.option("--owners", "-o", multiple=True, required=True)
@click.option("--people", "-p", multiple=True, required=True)
@click.option("--k", type=int, required=True)
@click.option("--description", "-d", required=True)
@click.pass_obj
def upload(client, file_path, owners, people, k, description):
    if client.upload_document(file_path, list(owners), list(people), k, description):
        console.print("[green]Upload success![/green]")
    else:
        console.print("[red]Upload failed![/red]")

@cli.command()
@click.pass_obj
def list_docs(client):
    client.show_documents()

@cli.command()
@click.option("--doc-id", type=int, required=True)
@click.option("--type", "-t", type=click.Choice(['read', 'write']), default='read')
@click.option("--hours", "-h", type=int, default=24)
@click.pass_obj
def request(client, doc_id, type, hours):
    if client.create_request(doc_id, type, hours):
        console.print("[green]Request created![/green]")
    else:
        console.print("[red]Request failed![/red]")

@cli.command()
@click.pass_obj
def pending(client):
    try:
        response = client.session.post(
            f"{BASE_URL}/other_requests/",
            json={"username": client.current_user[0], "passhash": generate_hash(client.current_user[1])}
        )
        requests = response.json()
        
        table = Table(title="Pending Requests")
        table.add_column("ID", style="cyan")
        table.add_column("Document")
        table.add_column("Requester")
        table.add_column("Type")
        
        for req in requests:
            req_type = "[yellow]READ[/yellow]" if req['req_type'] == "r" else "[red]WRITE[/red]"
            table.add_row(str(req['req_id']), req['filename'], req['user_id'], req_type)
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

@cli.command()
@click.option("--req-id", type=int, required=True)
@click.pass_obj
def approve(client, req_id):
    if client.sign_request(req_id):
        console.print("[green]Approved![/green]")
    else:
        console.print("[red]Approval failed![/red]")

@cli.command()
@click.option("--doc-id", type=int, required=True)
@click.pass_obj
def download(client, doc_id):
    if client.download_document(doc_id):
        console.print("[green]Download success![/green]")
    else:
        console.print("[red]Download failed![/red]")

if __name__ == "__main__":
    cli()