import requests
import click
import os
import base64
from rich.console import Console
from rich.table import Table
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from .models import *
from .hash_rsa import generate_hash, hash_to_rsa_key
from .Doc_encryption import encrypt_doc
from .SSS import spilt_secret, get_secret
from .Doc_Decryption import decrypt_doc, bitstring_to_bytes

BASE_URL = "http://127.0.0.1:8000"
console = Console()

class SecureVaultClient:
    def __init__(self):
        self.session = requests.Session()
        self.current_user = None
    
    def _make_request(self, method, url, **kwargs):
        """
        Centralized method for making HTTP requests with improved error handling
        """
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()  # Raise an exception for bad HTTP responses
            return response
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network Error: {str(e)}[/red]")
            return None
        except ValueError as e:
            console.print(f"[red]Response Error: {str(e)}[/red]")
            return None

    # --- Authentication ---
    def login(self, username: str, password: str) -> bool:
        try:
            user_data = User_F(
                username=username,
                passhash=generate_hash(password)
            )
            response = self._make_request(
                'POST', 
                f"{BASE_URL}/login/", 
                data=user_data.model_dump_json()
            )
            
            if response is None:
                return False
            
            login_result = response.json()
            if login_result:
                self.current_user = (username, password)
                return True
            return False
        except Exception as e:
            console.print(f"[red]Login error: {str(e)}[/red]")
            return False

    def signup(self, username: str, password: str) -> bool:
        try:
            private_key, public_key = hash_to_rsa_key(username, password)
            user_data = User(
                username=username,
                passhash=generate_hash(password),
                pb_key=public_key.export_key().decode()
            )
            response = self.session.post(
                f"{BASE_URL}/signup/",
                data=user_data.model_dump_json()
            )
            signup_result = response.json()
            return signup_result
        
        except Exception as e:
            console.print(f"[red]Signup error: {str(e)}[/red]")
            return False

    # --- Document Management ---
    def upload_document(self, file_path: str, owners: list[str], people: list[str], k: int, description: str) -> bool:
        try:
            # Existing validation logic
            if set(owners) & set(people):
                console.print("[red]Owners and people cannot overlap![/red]")
                return False

            # Encryption and secret splitting logic remains the same
            enc_file, key_iv_bits = encrypt_doc(file_path)
            
            sss_shares = spilt_secret(
                secret=key_iv_bits,
                no_of_owners=len(owners),
                k=k,
                n=len(people) + len(owners)
            )

            pb_keys = self.get_pbkeys(owners + people)
            if len(pb_keys) != len(owners + people):
                console.print("[red]Missing public keys![/red]")
                return False

            # Create upload data with enhanced error handling
            def _create_secret(share: str, username: str) -> user_secret:
                try:
                    cipher = PKCS1_OAEP.new(RSA.import_key(pb_keys[username].encode()))
                    encrypted = base64.b64encode(cipher.encrypt(share.encode())).decode()
                    return user_secret(username=username, user_secret=encrypted)
                except Exception as e:
                    console.print(f"[red]Secret creation error for {username}: {str(e)}[/red]")
                    raise

            upload_data = Upload_Doc(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                list_owners=[_create_secret(sss_shares['owner'][i], owner) for i, owner in enumerate(owners)],
                list_people=[_create_secret(sss_shares['people'][i], person) for i, person in enumerate(people)],
                k=k,
                filename=os.path.basename(file_path),
                description=description,
                l=len(key_iv_bits)
            )

            # More robust file upload
            try:
                with open(enc_file, "rb") as f:
                    response = self._make_request(
                        'POST',
                        f"{BASE_URL}/add_doc/",
                        data={"up_doc": upload_data.model_dump_json()}, # might have to change
                        files={"file": f} # check
                    )
                
                return response is not None and response.ok
            except IOError as e:
                console.print(f"[red]File access error: {str(e)}[/red]")
                return False

        except Exception as e:
            console.print(f"[red]Upload failed: {str(e)}[/red]")
            return False

    def download_document(self, doc_id: int) -> bool:
        try:
            docs_request = User_F(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1])
            )
            docs_response = self.session.post(
                f"{BASE_URL}/my_docs/",
                data=docs_request.model_dump_json()
            )

            if not docs_response.ok:
                console.print("[red]Metadata fetch failed![/red]")
                return False

            docs_data = Doc_User_Response(**docs_response.json())
            target_doc = next(
                (doc for doc in docs_data.owner + docs_data.people 
                 if doc.id == doc_id), None # check 
            )

            file_request = Doc_Fetch(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                doc_id=str(doc_id)
            )
            file_response = self.session.post(
                f"{BASE_URL}/get_file/",
                data=file_request.model_dump_json(),
                stream=True
            )

            encrypted_path = f"temp_{doc_id}.enc"
            with open(encrypted_path, "wb") as f:
                for chunk in file_response.iter_content(1024):
                    f.write(chunk)

            secrets_request = secret_Fetch(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                req_id=doc_id
            )
            secrets_response = self.session.post(
                f"{BASE_URL}/get_secrets/",
                data=secrets_request.model_dump_json()
            )

            shares_data = doc_secret(**secrets_response.json())
            sss_shares = {
                "owner": [s.user_secret for s in shares_data.list_owners],
                "people": [s.user_secret for s in shares_data.list_people],
                "k": target_doc.k,
                "o": target_doc.o,
                "l": target_doc.l
            }

            reconstructed = get_secret(sss_shares)
            key_iv_bytes = bitstring_to_bytes(reconstructed)
            key = key_iv_bytes[:32]
            iv = key_iv_bytes[32:40]

            decrypt_doc(encrypted_path, key, iv)
            console.print(f"[green]Decrypted file: {encrypted_path.replace('.enc', '_decrypted')}[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]Download failed: {str(e)}[/red]")
            return False

    def create_request(self, doc_id: int, req_type: str, valid_hours: int) -> bool:
        try:
            request_data = Req_F(
                user_id=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                doc_id=doc_id,
                req_type=Req_type(req_type.lower()),
                valid_time=valid_hours
            )
            response = self.session.post(
                f"{BASE_URL}/create_request/",
                data=request_data.model_dump_json()
            )
            return response.ok
        except Exception as e:
            console.print(f"[red]Request failed: {str(e)}[/red]")
            return False

    def sign_request(self, req_id: int) -> bool:
        try:
            requests_request = User_F(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1])
            )
            requests_response = self.session.post(
                f"{BASE_URL}/my_requests/",
                data=requests_request.model_dump_json()
            )
            
            target_request = next(
                (req for req in requests_response.json() 
                 if req['req_id'] == req_id), None
            )
            
            secret_request = Doc_Fetch(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                doc_id=target_request['doc_id']
            )
            secret_resp = self.session.post(
                f"{BASE_URL}/get_my_secret/",
                data=secret_request.model_dump_json()
            )

            private_key, _ = hash_to_rsa_key(*self.current_user)
            decrypted_secret = PKCS1_OAEP.new(private_key).decrypt(
                base64.b64decode(secret_resp.text)
            ).decode()

            sign_data = sign(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                req_id=req_id,
                encrypted_secret=decrypted_secret
            )
            response = self.session.post(
                f"{BASE_URL}/sign_req/",
                data=sign_data.model_dump_json()
            )
            return response.ok
            
        except Exception as e:
            console.print(f"[red]Signing failed: {str(e)}[/red]")
            return False

    # --- Helpers ---
    def get_pbkeys(self, usernames: list) -> dict:
        try:
            response = self.session.post(f"{BASE_URL}/pbkey/", json=usernames)
            return {u.username: u.pb_key for u in [user_pbkey(**item) for item in response.json()]}
        except:
            return {}

    def show_documents(self):
        try:
            docs_request = User_F(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1])
            )
            response = self.session.post(
                f"{BASE_URL}/my_docs/",
                data=docs_request.model_dump_json()
            )
            docs_data = Doc_User_Response(**response.json())
            
            table = Table(title="Your Documents")
            table.add_column("ID", style="cyan")
            table.add_column("Filename")
            table.add_column("Access Type")
            
            # Separate owner and people documents correctly
            for doc in docs_data.owner:
                table.add_row(str(doc.id), doc.filename, "[green]Owner[/green]")
            for doc in docs_data.people:
                table.add_row(str(doc.id), doc.filename, "[yellow]People[/yellow]")
            
            console.print(table)
        except Exception as e:
            console.print(f"[red]Load failed: {str(e)}[/red]")

    def show_pending_requests(self):
        try:
            request = User_F(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1])
            )
            response = self.session.post(
                f"{BASE_URL}/other_requests/",
                data=request.model_dump_json()
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

# CLI Implementation
@click.group()
@click.pass_context
def cli(ctx):
    """Secure Vault CLI"""
    ctx.obj = SecureVaultClient()

@cli.command()
@click.argument("username")
@click.argument("password")
def signup(username, password):
    """Register a new user"""
    if SecureVaultClient().signup(username, password):
        console.print(f"[green]Signed up {username}![/green]")
    else:
        console.print("[red]Signup failed![/red]")

@cli.command()
@click.argument("username")
@click.argument("password")
@click.pass_obj
def login(client, username, password):
    """Login to your account"""
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
    """Upload a document"""
    if client.upload_document(file_path, list(owners), list(people), k, description):
        console.print("[green]Upload success![/green]")
    else:
        console.print("[red]Upload failed![/red]")

@cli.command()
@click.pass_obj
def list_docs(client):
    """List your documents"""
    client.show_documents()

@cli.command()
@click.option("--doc-id", type=int, required=True)
@click.option("--type", "-t", type=click.Choice(['read', 'write']), default='read')
@click.option("--hours", "-h", type=int, default=24)
@click.pass_obj
def request(client, doc_id, type, hours):
    """Create access request"""
    if client.create_request(doc_id, type, hours):
        console.print("[green]Request created![/green]")
    else:
        console.print("[red]Request failed![/red]")

@cli.command()
@click.pass_obj
def pending(client):
    """Show pending requests needing your approval"""
    client.show_pending_requests()

@cli.command()
@click.option("--req-id", type=int, required=True)
@click.pass_obj
def approve(client, req_id):
    """Approve a request"""
    if client.sign_request(req_id):
        console.print("[green]Approved![/green]")
    else:
        console.print("[red]Approval failed![/red]")

@cli.command()
@click.option("--doc-id", type=int, required=True)
@click.pass_obj
def download(client, doc_id):
    """Download a document"""
    if client.download_document(doc_id):
        console.print("[green]Download success![/green]")
    else:
        console.print("[red]Download failed![/red]")

if __name__ == "__main__":
    cli()