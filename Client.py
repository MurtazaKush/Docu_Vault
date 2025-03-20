import requests
import click
from rich.console import Console
from hash_rsa import generate_hash, hash_to_rsa_key

BASE_URL = "http://127.0.0.1:8000"  # Change if server is hosted elsewhere
console = Console()

class SecureVaultClient:
    def signup(self, username: str, password: str):
        """Signup a new user."""
        # Hash the password
        passhash = generate_hash(password)
        
        # Generate RSA keys
        private_key, public_key = hash_to_rsa_key(username, password)
        pb_key = public_key.export_key().decode()  # Convert public key to string

        response = requests.post(f"{BASE_URL}/signup/", json={
            "username": username,
            "passhash": passhash,
            "pb_key": pb_key
        })
        if response.status_code == 200:
            console.print("[green]Signup successful![/green]")
        else:
            console.print(f"[red]Signup failed! {response.text}[/red]")

    def login(self, username: str, password: str):
        """Login a user."""
        # Hash the password
        passhash = generate_hash(password)

        response = requests.post(f"{BASE_URL}/login/", json={
            "username": username,
            "passhash": passhash
        })
        if response.status_code == 200 and response.json():
            console.print("[green]Login successful![/green]")
        else:
            console.print(f"[red]Login failed! {response.text}[/red]")

    def change_password(self, username: str, old_password: str, new_password: str):
        """Change user password and update secrets."""
        # Hash the old and new passwords
        old_passhash = generate_hash(old_password)
        new_passhash = generate_hash(new_password)

        # Generate new RSA keys
        private_key, public_key = hash_to_rsa_key(username, new_password)
        new_pb_key = public_key.export_key().decode()  # Convert public key to string

        # Fetch existing secrets
        response = requests.get(f"{BASE_URL}/change_pass/", json={
            "username": username,
            "passhash": old_passhash
        })
        if response.status_code != 200 or not response.json()["valid"]:
            console.print("[red]Invalid credentials or no secrets found.[/red]")
            return

        # Update secrets with new password
        updated_secrets = response.json()
        response = requests.post(f"{BASE_URL}/change_pass/", json={
            "username": username,
            "oldpasshash": old_passhash,
            "newpasshash": new_passhash,
            "updated_secret": updated_secrets,
            "newpb": new_pb_key
        })
        if response.status_code == 200 and response.json():
            console.print("[green]Password changed successfully![/green]")
        else:
            console.print(f"[red]Password change failed! {response.text}[/red]")

@click.group()
def cli():
    """Secure Document Vault CLI."""
    pass

@cli.command()
@click.argument("username")
@click.argument("password")
def signup(username, password):
    """Signup command."""
    SecureVaultClient().signup(username, password)

@cli.command()
@click.argument("username")
@click.argument("password")
def login(username, password):
    """Login command."""
    SecureVaultClient().login(username, password)

@cli.command()
@click.argument("username")
@click.argument("old_password")
@click.argument("new_password")
def change_password(username, old_password, new_password):
    """Change password command."""
    SecureVaultClient().change_password(username, old_password, new_password)

if __name__ == "__main__":
    cli()