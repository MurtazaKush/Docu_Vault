import os
import sys
import json
import time
import inquirer
import fire
import requests
import typer
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

console = Console()
API_BASE_URL = "http://localhost:8000"  # FastAPI backend URL (placeholder)
SESSION_FILE = "session.json"

class SecureVaultCLI:
    def __init__(self):
        self.username = None
        self.load_session()

    def load_session(self):
        """Load user session from file."""
        if os.path.exists(SESSION_FILE):
            try:
                with open(SESSION_FILE, "r") as f:
                    data = json.load(f)
                    self.username = data.get("username")
            except Exception:
                self.username = None

    def save_session(self):
        """Save user session to file."""
        with open(SESSION_FILE, "w") as f:
            json.dump({"username": self.username}, f)

    def clear_session(self):
        """Clear user session on logout."""
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)
        self.username = None

    def main(self):
        """Interactive Main Menu for the Secure Document Vault CLI."""
        while True:
            display_header("Secure Document Vault")
            # If not logged in, show authentication menu
            if not self.username:
                choice = inquirer.list_input(
                    "Select Option",
                    choices=["Register", "Login", "Exit"]
                )
                if choice == "Register":
                    self.register()
                elif choice == "Login":
                    self.login()
                else:
                    console.print("[bold red]Exiting...[/bold red]")
                    break
            else:
                # If logged in, show home menu
                self.home_menu()
                break

    def register(self):
        """Register a new user."""
        username = Prompt.ask("[bold cyan]Enter a new username[/]")
        password = Prompt.ask("[bold cyan]Enter a password[/]", password=True)
        console.print("[yellow]Registering user...[/yellow]")
        time.sleep(1)  # Simulate processing delay

        # Placeholder: Call your backend API for registration
        response = requests.post(f"{API_BASE_URL}/register", json={"username": username, "password": password})
        if response.status_code == 201:
            console.print(f"[green]User '{username}' registered successfully![/green]")
        else:
            console.print(f"[red]Error: {response.json().get('detail', 'Registration failed!')}[/red]")
        self.main()

    def login(self):
        """Login to the system."""
        username = Prompt.ask("[bold cyan]Enter your username[/]")
        password = Prompt.ask("[bold cyan]Enter your password[/]", password=True)
        console.print("[yellow]Logging in...[/yellow]")
        time.sleep(1)  # Simulate processing delay

        # Placeholder: Call your backend API for login
        response = requests.post(f"{API_BASE_URL}/login", json={"username": username, "password": password})
        if response.status_code == 200:
            self.username = username
            self.save_session()
            console.print(f"[green]Welcome, {username}![/green]")
            self.home_menu()
        else:
            console.print(f"[red]Error: {response.json().get('detail', 'Login failed!')}[/red]")
            self.main()

    def home_menu(self):
        """Should enter Home menu after successful login."""
        while True:
            display_header(f"Welcome, {self.username}")
            table = Table(title="Secure Vault - Main Menu")
            table.add_column("Option", style="cyan")
            table.add_column("Description", style="magenta")
            table.add_row("1", "Create New Document")
            table.add_row("2", "Approve Requests")
            table.add_row("3", "Request Access")
            table.add_row("4", "Logout")
            console.print(table)

            choice = Prompt.ask("[bold yellow]Select an option[/]")
            if choice == "1":
                self.create_document()
            elif choice == "2":
                self.approve_requests()
            elif choice == "3":
                self.request_access()
            elif choice == "4":
                console.print("[red]Logging out...[/red]")
                self.clear_session()
                break
            else:
                console.print("[red]Invalid choice! Try again.[/red]")

    def create_document(self):
        """Create and upload a document."""
        doc_name = Prompt.ask("[bold cyan]Enter document name[/bold cyan]")
        owners = Prompt.ask("[bold cyan]Enter owner usernames (comma-separated)[/bold cyan]").split(",")
        threshold_users = Prompt.ask("[bold cyan]Enter threshold users (comma-separated)[/bold cyan]").split(",")
        console.print(f"[yellow]Encrypting and uploading '{doc_name}'...[/yellow]")
        time.sleep(1)  # To simulate encryption delay adding sleep here

        # Call backend API for document upload
        response = requests.post(
            f"{API_BASE_URL}/upload_document",
            json={"username": self.username, "doc_name": doc_name, "owners": owners, "threshold_users": threshold_users},
        )
        if response.status_code == 201:
            console.print(f"[green]Document '{doc_name}' uploaded successfully![/green]")
        else:
            console.print(f"[red]Error: {response.json().get('detail', 'Upload failed!')}[/red]")
        self.home_menu()

    def approve_requests(self):
        """Approve pending access requests."""
        console.print("[blue]Fetching pending requests...[/blue]")
        response = requests.get(f"{API_BASE_URL}/pending_requests", params={"username": self.username})
        if response.status_code == 200:
            requests_list = response.json().get("requests", [])
            if not requests_list:
                console.print("[green]No pending requests![/green]")
                self.home_menu()
                return
            table = Table(title="Pending Requests")
            table.add_column("Request ID", style="cyan")
            table.add_column("Document", style="magenta")
            table.add_column("Requester", style="yellow")
            for req in requests_list:
                table.add_row(str(req["request_id"]), req["doc_name"], req["requester"])
            console.print(table)
            req_id = Prompt.ask("[bold cyan]Enter Request ID to approve (or 'q' to quit)[/bold cyan]")
            if req_id.lower() == "q":
                self.home_menu()
                return
            # Here the Approve request API call should be added
            response = requests.post(f"{API_BASE_URL}/approve_request", json={"request_id": req_id})
            if response.status_code == 200:
                console.print("[green]Request approved successfully![/green]")
            else:
                console.print(f"[red]Error: {response.json().get('detail', 'Approval failed!')}[/red]")
        else:
            console.print(f"[red]Error: {response.json().get('detail', 'Failed to fetch requests!')}[/red]")
        self.home_menu()

    def request_access(self):
        """Request access to a document."""
        doc_name = Prompt.ask("[bold cyan]Enter document name[/bold cyan]")
        console.print(f"[yellow]Requesting access to '{doc_name}'...[/yellow]")
        # Placeholder: Call backend API for access request
        response = requests.post(
            f"{API_BASE_URL}/request_access",
            json={"username": self.username, "doc_name": doc_name},
        )
        if response.status_code == 200:
            console.print("[green]Access request sent successfully![/green]")
        else:
            console.print(f"[red]Error: {response.json().get('detail', 'Request failed!')}[/red]")
        self.home_menu()

def display_header(title):
    console.print(f"\n[bold cyan]{'='*50}[/]")
    console.print(f"[bold yellow]{title.upper()}[/]")
    console.print(f"[bold cyan]{'='*50}[/]\n")

def interactive_mode():
    cli = SecureVaultCLI()
    cli.main()

if __name__ == "__main__":
    # If no command-line arguments, run interactive mode; otherwise, we will use Fire.
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        fire.Fire(SecureVaultCLI)
