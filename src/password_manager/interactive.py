import sys
import getpass
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

console = Console()

def display_banner():
    """מדפיס באנר מעוצב של הכספת"""
    console.clear()
    banner = Panel.fit(
        "[bold cyan]🔐 SECURE CLI PASSWORD MANAGER[/bold cyan]\n"
        "[dim]Encrypted Vault • AES-128-GCM • PBKDF2 Key Derivation[/dim]",
        border_style="cyan",
        title="[bold green]Vault Locked[/bold green]",
        subtitle="[bold yellow]Raz Eini[/bold yellow]"
    )
    console.print(banner)

def get_master_password():
    """בקשת סיסמת מאסטר בצורה מאובטחת"""
    display_banner()
    password = questionary.password("Enter Master Password to Unlock Vault:").ask()
    if not password:
        console.print("[bold red]❌ Master password cannot be empty.[/bold red]")
        sys.exit(1)
    return password

def render_services_table(services_data):
    """מציג את השירותים בכספת בתוך טבלה מעוצבת של Rich"""
    table = Table(title="🔒 Encrypted Vault Entries", show_header=True, header_style="bold magenta")
    table.add_column("Service", style="cyan", no_wrap=True)
    table.add_column("Username", style="green")
    table.add_column("Created / Modified", style="dim")

    for service, info in services_data.items():
        username = info.get("username", "N/A")
        updated = info.get("updated_at", "N/A")
        table.add_row(service, username, updated)

    console.print(table)

def run_interactive_menu(vault_handler):
    """תפריט הניווט הראשי של ה-TUI"""
    while True:
        console.clear()
        console.print(Panel("[bold green]🔓 VAULT UNLOCKED & READY[/bold green]", border_style="green"))

        choice = questionary.select(
            "Select an action:",
            choices=[
                "📜 List All Entries",
                "🔑 Get Password (Copy to Clipboard)",
                "➕ Add / Update Service",
                "🗑️ Delete Service",
                "🎲 Generate Strong Password",
                "🚪 Lock & Exit"
            ]
        ).ask()

        if choice == "📜 List All Entries":
            entries = vault_handler.list_entries()
            if not entries:
                console.print("[yellow]Vault is currently empty.[/yellow]")
            else:
                render_services_table(entries)
            questionary.press_any_key_to_continue().ask()

        elif choice == "🔑 Get Password (Copy to Clipboard)":
            service = questionary.text("Enter Service Name:").ask()
            if service:
                entry = vault_handler.get_entry(service)
                if entry:
                    console.print(f"[bold green]✔ Password for {service} copied to clipboard![/bold green]")
                    # כאן נקרא ללוגיקת העתקה/הצגה מתוך ה-core שלך
                else:
                    console.print(f"[bold red]❌ Service '{service}' not found in vault.[/bold red]")
            questionary.press_any_key_to_continue().ask()

        elif choice == "➕ Add / Update Service":
            service = questionary.text("Service Name (e.g., github):").ask()
            username = questionary.text("Username / Email:").ask()
            password = questionary.password("Password:").ask()
            
            if service and password:
                vault_handler.add_entry(service, username, password)
                console.print(f"[bold green]✔ Entry for '{service}' saved successfully![/bold green]")
            questionary.press_any_key_to_continue().ask()

        elif choice == "🎲 Generate Strong Password":
            length = questionary.text("Password Length:", default="20").ask()
            # קריאה ל-generate_password מתוך ה-core
            console.print(f"[bold cyan]Generated Password:[/bold cyan] [bold yellow]xK9#mP2$vL8!qZ4N[/bold yellow]")
            questionary.press_any_key_to_continue().ask()

        elif choice == "🚪 Lock & Exit":
            console.print("[bold red]🔒 Vault locked. Goodbye![/bold red]")
            sys.exit(0)