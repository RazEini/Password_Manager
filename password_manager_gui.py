"""
Password Manager - GUI (Tkinter)
================================
ממשק גרפי למנהל הסיסמאות הקיים שלך.
Vault חדש נוצר אוטומטית אם לא קיים.
"""

import tkinter as tk
from tkinter import messagebox, simpledialog
import pyperclip
from password_manager import Vault, generate_password

VAULT_FILE = "vault.json"

class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("600x400")
        self.resizable(False, False)

        self.vault = Vault(VAULT_FILE)
        self.master_password = None

        # Frames
        self.left_frame = tk.Frame(self)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        self.right_frame = tk.Frame(self)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Left: List of services
        tk.Label(self.left_frame, text="Services").pack()
        self.services_listbox = tk.Listbox(self.left_frame, width=25)
        self.services_listbox.pack(fill=tk.Y, expand=True)
        self.services_listbox.bind("<<ListboxSelect>>", self.on_service_select)

        # Buttons under list
        tk.Button(self.left_frame, text="Add", command=self.add_entry).pack(fill=tk.X, pady=2)
        tk.Button(self.left_frame, text="Delete", command=self.delete_entry).pack(fill=tk.X, pady=2)
        tk.Button(self.left_frame, text="Change Master Password", command=self.change_master_password).pack(fill=tk.X, pady=2)
        tk.Button(self.left_frame, text="Generate Password", command=self.show_generated_password).pack(fill=tk.X, pady=2)

        # Right: Entry details
        self.detail_text = tk.Text(self.right_frame, state="disabled", width=50, height=20)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        self.copy_button = tk.Button(self.right_frame, text="Copy Password", command=self.copy_password)
        self.copy_button.pack(pady=5)

        # Load or create vault
        self.login_or_create_vault()

    # --- Vault login or creation ---
    def login_or_create_vault(self):
        while True:
            try:
                if not self.vault.exists():
                    create = messagebox.askyesno("Vault not found", "Vault file not found. Create new vault?")
                    if create:
                        # GUI input for master password
                        while True:
                            master1 = simpledialog.askstring("Create Vault", "Enter new master password:", show="*")
                            if not master1 or len(master1) < 8:
                                messagebox.showwarning("Invalid", "Password must be at least 8 characters.")
                                continue
                            master2 = simpledialog.askstring("Confirm", "Confirm master password:", show="*")
                            if master1 != master2:
                                messagebox.showwarning("Mismatch", "Passwords do not match.")
                                continue
                            break
                        self.master_password = master1
                        self.vault.init_new(self.master_password)
                        messagebox.showinfo("Vault Created", f"Vault created at {VAULT_FILE}")
                    else:
                        self.destroy()
                        return
                else:
                    self.master_password = simpledialog.askstring("Master Password", "Enter master password:", show="*")
                self.refresh_services()
                break
            except Exception as e:
                messagebox.showerror("Error", str(e))

    # --- UI methods ---
    def refresh_services(self):
        self.services_listbox.delete(0, tk.END)
        try:
            services = self.vault.list_services(self.master_password)
            for svc in services:
                self.services_listbox.insert(tk.END, svc)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_service_select(self, event):
        selection = self.services_listbox.curselection()
        if selection:
            index = selection[0]
            service = self.services_listbox.get(index)
            try:
                entry = self.vault.get_entry(self.master_password, service)
                self.detail_text.config(state="normal")
                self.detail_text.delete("1.0", tk.END)
                self.detail_text.insert(tk.END, f"Service: {service}\n")
                self.detail_text.insert(tk.END, f"Username: {entry['username']}\n")
                self.detail_text.insert(tk.END, f"Password: {entry['password']}\n")
                self.detail_text.insert(tk.END, f"Notes: {entry.get('notes','')}\n")
                self.detail_text.config(state="disabled")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def add_entry(self):
        service = simpledialog.askstring("Service", "Service name:")
        if not service:
            return
        username = simpledialog.askstring("Username", "Username:")
        if username is None:
            return
        pwd_option = messagebox.askyesno("Password", "Generate strong password automatically?")
        if pwd_option:
            password = generate_password(length=20)
        else:
            password = simpledialog.askstring("Password", "Password:", show="*")
            if not password:
                return
        notes = simpledialog.askstring("Notes", "Notes (optional):") or ""
        try:
            self.vault.set_entry(self.master_password, service, username, password, notes)
            messagebox.showinfo("Success", f"Entry '{service}' saved.")
            self.refresh_services()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_entry(self):
        selection = self.services_listbox.curselection()
        if not selection:
            messagebox.showwarning("Select Service", "Please select a service to delete.")
            return
        index = selection[0]
        service = self.services_listbox.get(index)
        confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{service}'?")
        if confirm:
            try:
                self.vault.delete_entry(self.master_password, service)
                messagebox.showinfo("Deleted", f"Service '{service}' deleted.")
                self.refresh_services()
                self.detail_text.config(state="normal")
                self.detail_text.delete("1.0", tk.END)
                self.detail_text.config(state="disabled")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def copy_password(self):
        selection = self.services_listbox.curselection()
        if not selection:
            return
        index = selection[0]
        service = self.services_listbox.get(index)
        try:
            entry = self.vault.get_entry(self.master_password, service)
            pyperclip.copy(entry["password"])
            messagebox.showinfo("Copied", f"Password for '{service}' copied to clipboard.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def change_master_password(self):
        old = simpledialog.askstring("Old Password", "Enter old master password:", show="*")
        if old != self.master_password:
            messagebox.showerror("Error", "Old password incorrect")
            return
        new = simpledialog.askstring("New Password", "Enter new master password:", show="*")
        confirm = simpledialog.askstring("Confirm", "Confirm new master password:", show="*")
        if new != confirm:
            messagebox.showerror("Error", "New passwords do not match")
            return
        if len(new) < 8:
            messagebox.showerror("Error", "Password too short (min 8)")
            return
        try:
            self.vault.change_master(old, new)
            self.master_password = new
            messagebox.showinfo("Success", "Master password changed successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_generated_password(self):
        pwd = generate_password(length=20)
        messagebox.showinfo("Generated Password", pwd)


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
