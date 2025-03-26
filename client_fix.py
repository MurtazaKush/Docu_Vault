import requests
import click
import os
import time
import base64
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
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
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            return None

    def login(self, username: str, password: str) -> bool:
        user_data = User_F(username=username, passhash=generate_hash(password))
        response = self._make_request('POST', f"{BASE_URL}/login/", json=user_data.model_dump())
        if response and response.json():
            self.current_user = (username, password)
            return True
        return False

    def signup(self, username: str, password: str) -> bool:
        try:
            _, public_key = hash_to_rsa_key(username, password)
            user_data = User(
                username=username,
                passhash=generate_hash(password),
                pb_key=public_key.export_key().decode()
            )
            response = self._make_request('POST', f"{BASE_URL}/signup/", json=user_data.model_dump())
            return response.json() if response else False
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            return False

    def upload_document(self, file_path: str, owners: list[str], people: list[str], k: int, description: str) -> bool:
        try:
            enc_file, key_iv_bits = encrypt_doc(file_path)
            sss_shares = spilt_secret(key_iv_bits, len(owners), k, len(people)+len(owners))
            
            # CORRECT: Use the full share strings (secret + positions)
            owner_secrets = sss_shares['owner']
            people_secrets = sss_shares['people']
            
            pb_keys = self.get_pbkeys(owners + people)
            if len(pb_keys) != len(owners + people):
                console.print("[red]Missing public keys![/red]")
                return False

            def _create_secret(share: str, username: str):
                cipher = PKCS1_OAEP.new(RSA.import_key(pb_keys[username].encode()))
                encrypted = base64.b64encode(cipher.encrypt(share.encode())).decode()
                return user_secret(username=username, user_secret=encrypted)

            upload_data = Upload_Doc(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                list_owners=[_create_secret(s, o) for s, o in zip(owner_secrets, owners)],
                list_people=[_create_secret(s, p) for s, p in zip(people_secrets, people)],
                k=k,
                filename=os.path.basename(file_path),
                description=description,
                l=len(key_iv_bits)
            )

            with open(enc_file, "rb") as f:
                response = self._make_request(
                    'POST',
                    f"{BASE_URL}/add_doc/",
                    data={"up_doc": upload_data.model_dump_json()},
                    files={"file": f}
                )
            return response is not None
        except Exception as e:
            console.print(f"[red]Upload failed: {str(e)}[/red]")
            return False

    def download_document(self, doc_id: int) -> bool:
        try:
            # Create access request
            if not self.create_request(doc_id, "read", 24):
                console.print("[red]Failed to create request![/red]")
                return False

            # Wait for request approval
            req_id = None
            for _ in range(10):  # Wait max 50 seconds
                time.sleep(5)
                requests = self.get_my_requests()
                target_request = next((req for req in requests if req['doc_id'] == doc_id and req['status'] == "E_S"), None)
                if target_request:
                    req_id = target_request['req_id']
                    break
                console.print("[yellow]Waiting for approvals...[/yellow]")
            
            if not req_id:
                console.print("[red]Request not approved in time![/red]")
                return False

            # Fetch file
            file_request = Doc_Fetch(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                doc_id=str(doc_id)
            )
            file_response = self._make_request('POST', f"{BASE_URL}/get_file/", json=file_request.model_dump())
            if not file_response:
                return False

            encrypted_path = f"temp_{doc_id}.enc"
            with open(encrypted_path, "wb") as f:
                f.write(file_response.content)

            # Get secrets
            secrets_request = secret_Fetch(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                req_id=req_id
            )
            secrets_response = self._make_request('POST', f"{BASE_URL}/get_secrets/", json=secrets_request.model_dump())
            if not secrets_response:
                return False

            shares_data = doc_secret(**secrets_response.json())
            sss_shares = {
                "owner": [s.user_secret for s in shares_data.list_owners],
                "people": [s.user_secret for s in shares_data.list_people],
                "k": self.get_k(doc_id),
                "o": self.get_o(doc_id),
                "l": self.get_l(doc_id)
            }

            reconstructed = get_secret(sss_shares)
            key_iv_bytes = bitstring_to_bytes(reconstructed)
            key = key_iv_bytes[:32]
            iv = key_iv_bytes[32:40]

            output_path = decrypt_doc(encrypted_path, key, iv)
            console.print(f"[green]Decrypted file: {output_path}[/green]")
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
            response = self._make_request('POST', f"{BASE_URL}/create_request/", json=request_data.model_dump())
            return response.json() if response else False
        except Exception as e:
            console.print(f"[red]Request failed: {str(e)}[/red]")
            return False

    def sign_request(self, req_id: int) -> bool:
        try:
            # First get my secret for the document
            other_requests = self.get_other_requests()
            target_request = next((req for req in other_requests if req['req_id'] == req_id), None)
            
            if not target_request:
                console.print("[red]Request not found![/red]")
                return False

            secret_request = Doc_Fetch(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                doc_id=str(target_request['doc_id'])
            )
            secret_resp = self._make_request('POST', f"{BASE_URL}/get_my_secret/", json=secret_request.model_dump())

            if not secret_resp:
                console.print("[red]Failed to retrieve secret![/red]")
                return False

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
            response = self._make_request('POST', f"{BASE_URL}/sign_req/", json=sign_data.model_dump())
            return response.json() if response else False
            
        except Exception as e:
            console.print(f"[red]Signing failed: {str(e)}[/red]")
            return False

    def get_o(self, doc_id: int) -> int:
        try:
            doc_req = Doc_Fetch(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                doc_id=str(doc_id)
            )
            o_p_response = self._make_request('POST', f"{BASE_URL}/get_o_p/", json=doc_req.model_dump())
            doc = self.get_my_docs()
            target_doc = next((d for d in doc['people'] + doc['owner'] if d['id'] == doc_id), None)
            return target_doc['o'] if target_doc else 0
        except:
            return 0

    def get_k(self, doc_id: int) -> int:
        try:
            doc_req = Doc_Fetch(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1]),
                doc_id=str(doc_id)
            )
            o_p_response = self._make_request('POST', f"{BASE_URL}/get_o_p/", json=doc_req.model_dump())
            doc = self.get_my_docs()
            target_doc = next((d for d in doc['people'] + doc['owner'] if d['id'] == doc_id), None)
            return target_doc['k'] if target_doc else 0
        except:
            return 0

    def get_l(self, doc_id: int) -> int:
        try:
            doc = self.get_my_docs()
            target_doc = next((d for d in doc['people'] + doc['owner'] if d['id'] == doc_id), None)
            return target_doc['l'] if target_doc else 0
        except:
            return 0

    def get_pbkeys(self, usernames: list) -> dict:
        try:
            response = self._make_request('POST', f"{BASE_URL}/pbkey/", json=usernames)
            return {u.username: u.pb_key for u in [user_pbkey(**item) for item in response.json()]}
        except:
            return {}

    def get_my_docs(self):
        try:
            docs_request = User_F(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1])
            )
            response = self._make_request('POST', f"{BASE_URL}/my_docs/", json=docs_request.model_dump())
            return response.json() if response else {"owner": [], "people": []}
        except Exception as e:
            console.print(f"[red]Load failed: {str(e)}[/red]")
            return {"owner": [], "people": []}

    def get_my_requests(self):
        try:
            request = User_F(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1])
            )
            response = self._make_request('POST', f"{BASE_URL}/my_requests/", json=request.model_dump())
            return response.json() if response else []
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            return []

    def get_other_requests(self):
        try:
            request = User_F(
                username=self.current_user[0],
                passhash=generate_hash(self.current_user[1])
            )
            response = self._make_request('POST', f"{BASE_URL}/other_requests/", json=request.model_dump())
            return response.json() if response else []
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            return []

    def show_documents(self):
        try:
            docs_data = self.get_my_docs()
            
            table = Table(title="Your Documents")
            table.add_column("ID", style="cyan")
            table.add_column("Filename")
            table.add_column("Access Type")
            
            # Separate owner and people documents correctly
            for doc in docs_data.get('owner', []):
                table.add_row(str(doc['id']), doc['filename'], "[green]Owner[/green]")
            for doc in docs_data.get('people', []):
                table.add_row(str(doc['id']), doc['filename'], "[yellow]People[/yellow]")
            
            console.print(table)
        except Exception as e:
            console.print(f"[red]Load failed: {str(e)}[/red]")

    def show_pending_requests(self):
        try:
            requests = self.get_other_requests()
            
            table = Table(title="Pending Requests")
            table.add_column("ID", style="cyan")
            table.add_column("Document")
            table.add_column("Requester")
            table.add_column("Type")
            table.add_column("Status")
            
            for req in requests:
                req_type = "[yellow]READ[/yellow]" if req['req_type'] == "r" else "[red]WRITE[/red]"
                status_color = "[green]Signed[/green]" if req['signed'] else "[yellow]Pending[/yellow]"
                table.add_row(str(req['req_id']), req['filename'], req['user_id'], req_type, status_color)
            console.print(table)
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")

def main_menu():
    client = SecureVaultClient()
    
    while True:
        console.print("\n[bold]Main Menu[/bold]")
        choice = Prompt.ask(
            "1. Login\n2. Signup\n3. Exit\nEnter choice",
            choices=["1", "2", "3"],
            show_choices=False
        )
        
        if choice == "1":
            username = Prompt.ask("Username")
            password = Prompt.ask("Password", password=True)
            if client.login(username, password):
                logged_in_menu(client)
            else:
                console.print("[red]Login failed![/red]")
        elif choice == "2":
            username = Prompt.ask("New username")
            password = Prompt.ask("New password", password=True)
            if client.signup(username, password):
                console.print("[green]Signup successful![/green]")
            else:
                console.print("[red]Signup failed![/red]")
        elif choice == "3":
            break

def logged_in_menu(client):
    while True:
        console.print("\n[bold]Secure Vault[/bold]")
        choice = Prompt.ask(
            "1. Upload Document\n2. List Documents\n3. Download Document\n"
            "4. Pending Requests\n5. Approve Request\n6. Logout\nEnter choice",
            choices=["1", "2", "3", "4", "5", "6"],
            show_choices=False
        )
        
        if choice == "1":
            file_path = Prompt.ask("File path")
            owners = Prompt.ask("Owners (comma separated)").split(',')
            people = Prompt.ask("People (comma separated)").split(',')
            k = int(Prompt.ask("Threshold (k)"))
            desc = Prompt.ask("Description")
            if client.upload_document(file_path, owners, people, k, desc):
                console.print("[green]Upload successful![/green]")
            else:
                console.print("[red]Upload failed![/red]")
                
        elif choice == "2":
            client.show_documents()
            
        elif choice == "3":
            doc_id = int(Prompt.ask("Document ID"))
            if client.download_document(doc_id):
                console.print("[green]Download successful![/green]")
            else:
                console.print("[red]Download failed![/red]")
                
        elif choice == "4":
            client.show_pending_requests()
            
        elif choice == "5":
            req_id = int(Prompt.ask("Request ID"))
            if client.sign_request(req_id):
                console.print("[green]Approval successful![/green]")
            else:
                console.print("[red]Approval failed![/red]")
                
        elif choice == "6":
            break

if __name__ == "__main__":
    main_menu()