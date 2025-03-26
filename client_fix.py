import requests
import os
import time
import base64
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from models import *
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
        self.current_privkey = None

    def _make_request(self, method, url, **kwargs):
        """Unified request handler with enhanced error reporting"""
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            console.print(f"[red]HTTP Error {e.response.status_code}: {e.response.text}[/red]")
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network Error: {str(e)}[/red]")
        return None

    # ----- Authentication Flow -----
    def handle_authentication(self):
        while True:
            console.print("\n[bold cyan]Main Menu[/bold cyan]")
            choice = Prompt.ask(
                "1. Login\n2. Signup\n3. Exit",
                choices=["1", "2", "3"],
                show_choices=False
            )
            
            if choice == "1":
                self._handle_login()
            elif choice == "2":
                self._handle_signup()
            elif choice == "3":
                exit()

    def _handle_signup(self):
        console.print("\n[bold]New User Registration[/bold]")
        username = Prompt.ask("Enter username")
        if not username:
            console.print("[red]Username cannot be empty![/red]")
            return
            
        password = Prompt.ask("Enter password", password=True)
        if len(password) < 8:
            console.print("[red]Password must be at least 8 characters![/red]")
            return

        try:
            # Generate 4096-bit RSA keys
            private_key, public_key = hash_to_rsa_key(username, password)
            user_data = User(
                username=username,
                passhash=generate_hash(password),
                pb_key=public_key.export_key().decode()
            )
            
            if self._make_request('POST', f"{BASE_URL}/signup/", json=user_data.model_dump()):
                console.print(f"[green]Successfully registered {username}![/green]")
            else:
                console.print("[red]Username already exists![/red]")
        except Exception as e:
            console.print(f"[red]Registration failed: {str(e)}[/red]")

    def _handle_login(self):
        console.print("\n[bold]User Login[/bold]")
        username = Prompt.ask("Username")
        password = Prompt.ask("Password", password=True)
        
        user_data = User_F(
            username=username,
            passhash=generate_hash(password)
        )
        
        if self._make_request('POST', f"{BASE_URL}/login/", json=user_data.model_dump()):
            self.current_user = (username, password)
            self.current_privkey = hash_to_rsa_key(username, password)[0]
            console.print(f"[green]Welcome {username}![/green]")
            self._logged_in_interface()
        else:
            console.print("[red]Invalid credentials![/red]")

    # ----- Password Management -----
    def handle_password_change(self):
        console.print("\n[bold orange3]Password Update[/bold orange3]")
        current_pass = Prompt.ask("Current password", password=True)
        new_pass = Prompt.ask("New password", password=True)
        
        if not self._validate_password(new_pass):
            return

        try:
            # Get existing secrets for re-encryption
            secrets = self._make_request(
                'POST', 
                f"{BASE_URL}/change_pass_get/",
                json=User_F(
                    username=self.current_user[0],
                    passhash=generate_hash(current_pass)
                ).model_dump()
            ).json()
            
            # Generate new keys
            new_priv, new_pub = hash_to_rsa_key(self.current_user[0], new_pass)
            cipher_old = PKCS1_OAEP.new(self.current_privkey)
            cipher_new = PKCS1_OAEP.new(new_pub)

            # Re-encrypt all secrets
            updated_secrets = secret_list(**secrets)
            for secret in updated_secrets.owner_secret + updated_secrets.people_secret:
                decrypted = cipher_old.decrypt(base64.b64decode(secret.encrypted_secret))
                secret.encrypted_secret = base64.b64encode(cipher_new.encrypt(decrypted)).decode()

            # Submit changes
            change_data = User_CP(
                username=self.current_user[0],
                oldpasshash=generate_hash(current_pass),
                newpasshash=generate_hash(new_pass),
                updated_secret=updated_secrets,
                newpb=new_pub.export_key().decode()
            )
            
            if self._make_request('POST', f"{BASE_URL}/change_pass/", json=change_data.model_dump()):
                self.current_user = (self.current_user[0], new_pass)
                console.print("[green]Password updated successfully![/green]")
        except Exception as e:
            console.print(f"[red]Password change failed: {str(e)}[/red]")

    # ----- Document Management -----
    def handle_document_upload(self):
        console.print("\n[bold]Document Upload[/bold]")
        file_path = Prompt.ask("Full file path")
        if not os.path.exists(file_path):
            console.print("[red]File not found![/red]")
            return

        owners = self._get_valid_users("Enter owners (comma-separated)")
        people = self._get_valid_users("Enter people (comma-separated)")
        k = Prompt.ask("Threshold (k)", default=str(len(people)), show_default=True)
        
        try:
            # Encrypt file and split secret
            enc_file, key_iv_bits = encrypt_doc(file_path)
            sss_shares = spilt_secret(
                key_iv_bits,
                len(owners),
                int(k),
                len(owners)+len(people))
            
            # Encrypt shares with recipients' public keys
            pb_keys = self._get_public_keys(owners + people)
            encrypted_shares = {
                'owners': [self._encrypt_share(sss_shares['owner'][i], u, pb_keys[u]) 
                          for i, u in enumerate(owners)],
                'people': [self._encrypt_share(sss_shares['people'][i], u, pb_keys[u])
                          for i, u in enumerate(people)]
            }

            # Prepare upload payload
            upload_data = Upload_Doc(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                list_owners=[user_secret(username=u, user_secret=s) 
                           for u, s in encrypted_shares['owners']],
                list_people=[user_secret(username=u, user_secret=s)
                           for u, s in encrypted_shares['people']],
                k=int(k),
                filename=os.path.basename(file_path),
                description=Prompt.ask("Document description"),
                l=len(key_iv_bits)
            )

            # Execute upload
            with open(enc_file, "rb") as f:
                if self._make_request(
                    'POST', 
                    f"{BASE_URL}/add_doc/",
                    data={"up_doc": upload_data.model_dump_json()},
                    files={"file": f}
                ):
                    console.print("[green]Document uploaded successfully![/green]")
                    os.remove(enc_file)
        except Exception as e:
            console.print(f"[red]Upload failed: {str(e)}[/red]")

    # ----- Request System -----
    def handle_access_request(self):
        console.print("\n[bold]New Access Request[/bold]")
        doc_id = Prompt.ask("Document ID")
        req_type = Prompt.ask("Request type (read/write)", choices=["read", "write"])
        hours = Prompt.ask("Validity hours", default="24")
        
        try:
            request_data = Req_F(
                user_id=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                doc_id=int(doc_id),
                req_type=Req_type(req_type.lower()),
                valid_time=int(hours)
            )
            
            if self._make_request('POST', f"{BASE_URL}/create_request/", json=request_data.model_dump()):
                console.print("[green]Request created! Check 'My Requests' for status[/green]")
        except Exception as e:
            console.print(f"[red]Request failed: {str(e)}[/red]")

    # ----- Document Retrieval -----
    def handle_document_download(self):
        console.print("\n[bold]Document Download[/bold]")
        doc_id = Prompt.ask("Document ID")
        
        try:
            # Create read request
            if not self.create_request(int(doc_id), "read", 24):
                console.print("[red]Failed to initiate download request![/red]")
                return

            # Monitor request status
            console.print("[yellow]Waiting for required approvals...[/yellow]")
            req_id = None
            for _ in range(12):  # 1 minute timeout
                time.sleep(5)
                reqs = self.get_my_requests()
                target = next((r for r in reqs if r.doc_id == int(doc_id) and r.status == "E_S"), None)
                if target:
                    req_id = target.req_id
                    break

            if not req_id:
                console.print("[red]Request timed out or denied![/red]")
                return

            # Retrieve encrypted file
            file_response = self._make_request(
                'POST', 
                f"{BASE_URL}/get_file/",
                json=Doc_Fetch(
                    username=self.current_user[0],
                    passhash=generate_hash(self.current_user[1]),
                    doc_id=doc_id
                ).model_dump()
            )
            
            # Save encrypted content
            enc_path = f"temp_{doc_id}.enc"
            with open(enc_path, "wb") as f:
                f.write(file_response.content)

            # Retrieve secret shares
            secrets = self._make_request(
                'POST',
                f"{BASE_URL}/get_secrets/",
                json=secret_Fetch(
                    username=self.current_user[0],
                    passhash=generate_hash(self.current_user[1]),
                    req_id=req_id
                ).model_dump()
            ).json()

            # Reconstruct encryption key
            reconstructed = get_secret({
                "owner": [s['user_secret'] for s in secrets['list_owners']],
                "people": [s['user_secret'] for s in secrets['list_people']],
                "k": self._get_doc_param(doc_id, 'k'),
                "o": self._get_doc_param(doc_id, 'o'),
                "l": self._get_doc_param(doc_id, 'l')
            })
            
            # Decrypt and save
            key_iv_bytes = bitstring_to_bytes(reconstructed)
            dec_path = decrypt_doc(enc_path, key_iv_bytes[:32], key_iv_bytes[32:40])
            console.print(f"[green]Document decrypted to: {dec_path}[/green]")
            os.remove(enc_path)
            
        except Exception as e:
            console.print(f"[red]Download failed: {str(e)}[/red]")

    # ----- User Interface -----
    def _logged_in_interface(self):
        while True:
            console.print("\n[bold cyan]Secure Vault Interface[/bold cyan]")
            choice = Prompt.ask(
                "1. My Documents\n2. Upload Document\n3. Download Document\n"
                "4. Create Request\n5. View My Requests\n6. Pending Approvals\n"
                "7. Change Password\n8. Logout",
                choices=["1", "2", "3", "4", "5", "6", "7", "8"],
                show_choices=False
            )
            
            if choice == "1":
                self._display_documents()
            elif choice == "2":
                self.handle_document_upload()
            elif choice == "3":
                self.handle_document_download()
            elif choice == "4":
                self.handle_access_request()
            elif choice == "5":
                self._display_my_requests()
            elif choice == "6":
                self._display_pending_approvals()
            elif choice == "7":
                self.handle_password_change()
            elif choice == "8":
                self.current_user = None
                console.print("[yellow]Logged out successfully[/yellow]")
                return

    # ----- Helper Methods -----
    def _display_documents(self):
        docs = self._make_request(
            'POST', 
            f"{BASE_URL}/my_docs/",
            json=User_F(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1])
            ).model_dump()
        ).json()
        
        table = Table(title="Your Documents", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan")
        table.add_column("Filename")
        table.add_column("Access Type")
        table.add_column("Status")
        
        for doc in docs['owner'] + docs['people']:
            access_type = "[green]Owner[/green]" if doc in docs['owner'] else "[yellow]People[/yellow]"
            status = "[green]Accessible[/green]" if doc['accessible'] else "[red]Locked[/red]"
            table.add_row(str(doc['id']), doc['filename'], access_type, status)
        
        console.print(table)

    def _display_my_requests(self):
        reqs = self.get_my_requests()
        table = Table(title="Active Requests", show_header=True, header_style="bold magenta")
        table.add_column("Req ID", style="cyan")
        table.add_column("Document")
        table.add_column("Type")
        table.add_column("Expires In")
        
        for req in reqs:
            remaining = (datetime.fromisoformat(req.req_time) + timedelta(hours=req.valid_time) - datetime.now())
            table.add_row(
                str(req.req_id),
                req.filename,
                "[blue]READ[/blue]" if req.req_type == "r" else "[red]WRITE[/red]",
                f"{remaining.seconds//3600}h {(remaining.seconds//60)%60}m"
            )
        
        console.print(table)

    def _display_pending_approvals(self):
        reqs = self.get_pending_requests()
        table = Table(title="Pending Approvals", show_header=True, header_style="bold magenta")
        table.add_column("Req ID", style="cyan")
        table.add_column("Document")
        table.add_column("Requester")
        table.add_column("Required Action")
        
        for req in reqs:
            action = "[yellow]Owner Approval[/yellow]" if req.user_type == "o" else "[cyan]Threshold Approval[/cyan]"
            table.add_row(str(req.req_id), req.filename, req.user_id, action)
        
        console.print(table)
        if reqs and Confirm.ask("Sign any requests?"):
            req_id = Prompt.ask("Enter Request ID")
            self._handle_request_signing(req_id)

    def _handle_request_signing(self, req_id: int):
        try:
            # Retrieve secret
            secret = self._make_request(
                'POST',
                f"{BASE_URL}/get_my_secret/",
                json=Doc_Fetch(
                    username=self.current_user[0],
                    passhash=generate_hash(self.current_user[1]),
                    doc_id=req_id
                ).model_dump()
            ).text
            
            # Decrypt and resubmit
            decrypted = PKCS1_OAEP.new(self.current_privkey).decrypt(base64.b64decode(secret))
            if self._make_request(
                'POST',
                f"{BASE_URL}/sign_req/",
                json=sign(
                    username=self.current_user[0],
                    passhash=generate_hash(self.current_user[1]),
                    req_id=req_id,
                    encrypted_secret=decrypted.decode()
                ).model_dump()
            ):
                console.print("[green]Approval submitted![/green]")
        except Exception as e:
            console.print(f"[red]Approval failed: {str(e)}[/red]")

    def _get_public_keys(self, users: list) -> dict:
        response = self._make_request('POST', f"{BASE_URL}/pbkey/", json=users)
        return {u['username']: u['pb_key'] for u in response.json()} if response else {}

    def _encrypt_share(self, share: str, username: str, pub_key: str) -> str:
        cipher = PKCS1_OAEP.new(RSA.import_key(pub_key.encode()))
        return base64.b64encode(cipher.encrypt(share.encode())).decode()

    def _get_doc_param(self, doc_id: int, param: str) -> int:
        docs = self._make_request(
            'POST', 
            f"{BASE_URL}/my_docs/",
            json=User_F(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1])
            ).model_dump()
        ).json()
        
        for doc in docs['owner'] + docs['people']:
            if doc['id'] == doc_id:
                return doc.get(param, 0)
        return 0

    def _validate_password(self, password: str) -> bool:
        if len(password) < 8:
            console.print("[red]Password must be at least 8 characters![/red]")
            return False
        return True

    def _get_valid_users(self, prompt: str) -> list:
        while True:
            users = [u.strip() for u in Prompt.ask(prompt).split(',')]
            if users:
                return users
            console.print("[red]Please enter at least one user![/red]")

    def get_my_requests(self):
        request = User_F(
            username=self.current_user[0],
            passhash=generate_hash(self.current_user[1])
        )
        response = self._make_request('POST', f"{BASE_URL}/my_requests/", json=request.model_dump())
        return [myRequest_User_View(**item) for item in response.json()] if response else []

    def get_pending_requests(self):
        request = User_F(
            username=self.current_user[0],
            passhash=generate_hash(self.current_user[1])
        )
        response = self._make_request('POST', f"{BASE_URL}/other_requests/", json=request.model_dump())
        return [Request_User_View(**item) for item in response.json()] if response else []

    def create_request(self, doc_id: int, req_type: str, valid_hours: int) -> bool:
        try:
            request_data = Req_F(
                user_id=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                doc_id=doc_id,
                req_type=Req_type(req_type.lower()),
                valid_time=valid_hours
            )
            return self._make_request('POST', f"{BASE_URL}/create_request/", json=request_data.model_dump()) is not None
        except:
            return False

if __name__ == "__main__":
    client = SecureVaultClient()
    client.handle_authentication()