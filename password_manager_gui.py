"""
Password Manager - GUI (Tkinter)
================================
ממשק גרפי למנהל הסיסמאות הקיים שלך.
Vault חדש נוצר אוטומטית אם לא קיים.
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
import pyperclip
import secrets
import string
from password_manager import Vault  # הסרנו את generate_password – יש לנו מחולל מותאם כאן

VAULT_FILE = "vault.json"

# --- פונקציה לבדיקת חוזק סיסמה ---
def check_password_strength(password):
    """
    מחזירה (ok, reasons)
    ok = True אם הסיסמה חזקה
    reasons = רשימה של מה שחסר
    """
    reasons = []
    if len(password) < 8:
        reasons.append("Password too short (min 8 chars)")
    if not any(c.islower() for c in password):
        reasons.append("Missing lowercase letter")
    if not any(c.isupper() for c in password):
        reasons.append("Missing uppercase letter")
    if not any(c.isdigit() for c in password):
        reasons.append("Missing digit")
    if not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~`" for c in password):
        reasons.append("Missing special character")
    ok = len(reasons) == 0
    return ok, reasons


# --- מחולל סיסמא מותאם אישית (קריפטוגרפי) ---
SAFE_SYMBOLS = "!@#$%^&*()_-+=[]{}:;.,?/|~<>"

def generate_custom_password(length=12, use_lower=True, use_upper=True, use_digits=True, use_symbols=True):
    if length < 6:
        raise ValueError("Minimum length is 6")
    pools = []
    alphabet = ""

    if use_lower:
        pools.append(string.ascii_lowercase)
        alphabet += string.ascii_lowercase
    if use_upper:
        pools.append(string.ascii_uppercase)
        alphabet += string.ascii_uppercase
    if use_digits:
        pools.append(string.digits)
        alphabet += string.digits
    if use_symbols:
        pools.append(SAFE_SYMBOLS)
        alphabet += SAFE_SYMBOLS

    if not alphabet:
        raise ValueError("חייב לבחור לפחות סוג תווים אחד!")

    # הבטחת גיוון – לפחות תו אחד מכל קטגוריה שנבחרה
    pwd_chars = [secrets.choice(pool) for pool in pools]
    while len(pwd_chars) < length:
        pwd_chars.append(secrets.choice(alphabet))
    secrets.SystemRandom().shuffle(pwd_chars)
    return "".join(pwd_chars[:length])


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

        # Help button (🔍) בפינה הימנית העליונה
        help_button = tk.Button(self, text="🔍", font=("Arial", 14), command=self.show_help)
        help_button.place(relx=1.0, rely=0.0, x=-10, y=10, anchor="ne")

        # Load or create vault
        self.login_or_create_vault()

    # --- Custom dialog for password/input with eye toggle, centered ---
    def ask_password(self, title="Enter Password", prompt="Password:", is_password=True, show_strength=False):
        top = tk.Toplevel(self)
        top.title(title)
        top.geometry("350x250")
        top.resizable(False, False)
        top.grab_set()

        # --- Center the dialog ---
        top.update_idletasks()
        try:
            parent_x = self.winfo_x()
            parent_y = self.winfo_y()
            parent_width = self.winfo_width()
            parent_height = self.winfo_height()
        except Exception:
            parent_x = parent_y = 0
            parent_width = self.winfo_screenwidth()
            parent_height = self.winfo_screenheight()

        x = parent_x + (parent_width // 2) - (350 // 2)
        y = parent_y + (parent_height // 2) - (250 // 2)
        top.geometry(f"+{x}+{y}")

        tk.Label(top, text=prompt).pack(pady=5)

        entry_var = tk.StringVar()
        entry = tk.Entry(top, textvariable=entry_var, show="*" if is_password else "")
        entry.pack(pady=5)
        entry.focus()

        # Toggle show/hide password
        if is_password:
            def toggle_password():
                if entry.cget("show") == "":
                    entry.config(show="*")
                    toggle_btn.config(text="הראה סיסמא")
                else:
                    entry.config(show="")
                    toggle_btn.config(text="הסתר סיסמא")

            toggle_btn = tk.Button(top, text="הראה סיסמא", command=toggle_password)
            toggle_btn.pack()

        # --- Strength checker עם scrollable Text ---
        if show_strength and is_password:
            strength_label = tk.Label(top, text="Strength: ", fg="gray")
            strength_label.pack(pady=2)

            missing_text = scrolledtext.ScrolledText(top, height=5, width=40, fg="red")
            missing_text.pack(pady=2)
            missing_text.config(state="disabled")

            def update_strength(event=None):
                pwd = entry_var.get()
                ok, reasons = check_password_strength(pwd)
                missing_text.config(state="normal")
                missing_text.delete("1.0", tk.END)
                if not pwd:
                    strength_label.config(text="Strength: ", fg="gray")
                    entry.config(bg="white")
                elif ok:
                    strength_label.config(text="Strength: Strong", fg="green")
                    entry.config(bg="#d4edda")
                else:
                    strength_label.config(text="Strength: Weak", fg="red")
                    missing_text.insert(tk.END, "\n".join("- "+r for r in reasons))
                    entry.config(bg="#f8d7da")
                missing_text.config(state="disabled")

            entry.bind("<KeyRelease>", update_strength)

        result = {"value": None}

        # --- OK/Cancel buttons ---
        def on_ok():
            value = entry_var.get()
            if show_strength and is_password:
                ok, reasons = check_password_strength(value)
                if not ok:
                    messagebox.showwarning("Weak password", "Password is too weak:\n" + "\n".join(reasons))
                    return  # לא סוגר את החלון
            result["value"] = value
            top.destroy()

        def on_cancel():
            result["value"] = None
            top.destroy()

        button_frame = tk.Frame(top)
        button_frame.pack(pady=10, fill=tk.X)
        tk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, expand=True, padx=10)
        tk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, expand=True, padx=10)

        top.wait_window()
        return result["value"]

    # --- דיאלוג גנרטור סיסמאות מותאם אישית (החזר סיסמה או None) ---
    def open_password_generator(self, title="Password Generator"):
        top = tk.Toplevel(self)
        top.title(title)
        top.geometry("380x360")
        top.resizable(False, False)
        top.grab_set()

        # Center
        top.update_idletasks()
        try:
            parent_x = self.winfo_x()
            parent_y = self.winfo_y()
            parent_w = self.winfo_width()
            parent_h = self.winfo_height()
        except Exception:
            parent_x = parent_y = 0
            parent_w = self.winfo_screenwidth()
            parent_h = self.winfo_screenheight()
        x = parent_x + (parent_w // 2) - (380 // 2)
        y = parent_y + (parent_h // 2) - (360 // 2)
        top.geometry(f"+{x}+{y}")

        tk.Label(top, text="Customize Your Password", font=("Arial", 12, "bold")).pack(pady=8)

        # Length
        length_frame = tk.Frame(top)
        length_frame.pack(fill="x", padx=16)
        tk.Label(length_frame, text="Length:").pack(side="left")
        length_var = tk.IntVar(value=16)
        length_scale = tk.Scale(length_frame, from_=8, to=64, orient="horizontal", variable=length_var)
        length_scale.pack(side="left", fill="x", expand=True, padx=8)

        # Options
        opts = tk.Frame(top)
        opts.pack(fill="x", padx=16, pady=4)
        use_lower = tk.BooleanVar(value=True)
        use_upper = tk.BooleanVar(value=True)
        use_digits = tk.BooleanVar(value=True)
        use_symbols = tk.BooleanVar(value=True)
        tk.Checkbutton(opts, text="Lowercase (a-z)", variable=use_lower).grid(row=0, column=0, sticky="w", pady=2)
        tk.Checkbutton(opts, text="Uppercase (A-Z)", variable=use_upper).grid(row=1, column=0, sticky="w", pady=2)
        tk.Checkbutton(opts, text="Digits (0-9)", variable=use_digits).grid(row=0, column=1, sticky="w", padx=16, pady=2)
        tk.Checkbutton(opts, text="Symbols (!@#$…)", variable=use_symbols).grid(row=1, column=1, sticky="w", padx=16, pady=2)

        # Preview
        tk.Label(top, text="Preview:").pack(anchor="w", padx=16, pady=(8, 0))
        preview_var = tk.StringVar(value="")
        preview_entry = tk.Entry(top, textvariable=preview_var, font=("Consolas", 11))
        preview_entry.pack(fill="x", padx=16, pady=6)

        # Buttons
        btns = tk.Frame(top)
        btns.pack(pady=8)

        def regenerate():
            try:
                pwd = generate_custom_password(
                    length=length_var.get(),
                    use_lower=use_lower.get(),
                    use_upper=use_upper.get(),
                    use_digits=use_digits.get(),
                    use_symbols=use_symbols.get()
                )
                preview_var.set(pwd)
            except ValueError as e:
                messagebox.showerror("Error", str(e), parent=top)

        def copy_to_clipboard():
            txt = preview_var.get()
            if not txt:
                regenerate()
                txt = preview_var.get()
            if txt:
                pyperclip.copy(txt)
                messagebox.showinfo("Copied", "Password copied to clipboard.", parent=top)

        result = {"value": None}

        def use_and_close():
            if not preview_var.get():
                regenerate()
            result["value"] = preview_var.get()
            top.destroy()

        def cancel():
            result["value"] = None
            top.destroy()

        tk.Button(btns, text="Generate", command=regenerate, width=12).pack(side="left", padx=5)
        tk.Button(btns, text="Copy", command=copy_to_clipboard, width=12).pack(side="left", padx=5)
        tk.Button(btns, text="Use", command=use_and_close, width=12).pack(side="left", padx=5)
        tk.Button(btns, text="Cancel", command=cancel, width=12).pack(side="left", padx=5)

        # Auto-generate first preview
        self.after(50, regenerate)

        top.wait_window()
        return result["value"]

    # --- Vault login or creation ---
    def login_or_create_vault(self):
        try:
            if not self.vault.exists():
                create = messagebox.askyesno("Vault not found", "Vault file not found.\nDo you want to create a new vault?")
                if not create:
                    self.destroy()
                    return

                while True:
                    master1 = self.ask_password("Create Vault", "Enter new master password:", is_password=True, show_strength=True)
                    if master1 is None:
                        self.destroy()
                        return
                    ok, _ = check_password_strength(master1)
                    if not ok:
                        messagebox.showwarning("Weak password", "Password is too weak, please follow the strength rules.")
                        continue
                    master2 = self.ask_password("Confirm Vault", "Confirm master password:", is_password=True)
                    if master1 != master2:
                        messagebox.showwarning("Mismatch", "Passwords do not match.")
                        continue
                    break

                self.master_password = master1
                self.vault.init_new(self.master_password)
                messagebox.showinfo("Vault Created", f"Vault created at {VAULT_FILE}")

            else:
                self.master_password = self.ask_password("Master Password", "Enter master password:", is_password=True)
                if self.master_password is None:
                    self.destroy()
                    return

            self.refresh_services()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.destroy()

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
        service = self.ask_password("Add Service", "Service name:", is_password=False)
        if not service:
            return
        username = self.ask_password("Add Service", "Username:", is_password=False)
        if username is None:
            return

        # קודם מציעים את מחולל הסיסמאות המותאם; אם בוטל – קליטה ידנית עם בדיקת חוזק
        password = self.open_password_generator(title="Generate Password for New Entry")
        if not password:
            password = self.ask_password("Add Service", "Password:", is_password=True, show_strength=True)
            if not password:
                return

        notes = self.ask_password("Add Service", "Notes (optional):", is_password=False) or ""
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
        old = self.ask_password("Old Password", "Enter old master password:", is_password=True)
        if old != self.master_password:
            messagebox.showerror("Error", "Old password incorrect")
            return
        new = self.ask_password("New Password", "Enter new master password:", is_password=True, show_strength=True)
        confirm = self.ask_password("Confirm Password", "Confirm new master password:", is_password=True)
        if new != confirm:
            messagebox.showerror("Error", "New passwords do not match")
            return
        ok, _ = check_password_strength(new)
        if not ok:
            messagebox.showerror("Error", "New password is too weak")
            return
        try:
            self.vault.change_master(old, new)
            self.master_password = new
            messagebox.showinfo("Success", "Master password changed successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_generated_password(self):
        """כפתור הצד: פותח את מחולל הסיסמאות המותאם, מציג ומעתיק בלחיצה"""
        pwd = self.open_password_generator(title="Password Generator")
        if pwd:
            pyperclip.copy(pwd)
            messagebox.showinfo("Generated Password", f"Password copied to clipboard:\n\n{pwd}")

    def show_help(self):
        help_text = (
            "🔑 אפליקציית ניהול הסיסמאות:\n\n"
            "1. 'Add' – הוספת אתר, שם משתמש וסיסמה.\n"
            "2. 'Delete' – מחיקה של סיסמה קיימת.\n"
            "3. 'Change Master Password' – שינוי סיסמת המאסטר.\n"
            "4. 'Generate Password' – יצירת סיסמה חזקה מותאמת אישית.\n"
            "5. בחירה ברשימת השירותים משמאל – מציגה את הפרטים המלאים.\n"
            "6. 'Copy Password' – מעתיק את הסיסמה ללוח.\n\n"
            "📌 כל הסיסמאות נשמרות בצורה מוצפנת ומאובטחת."
        )
        messagebox.showinfo("עזרה - איך להשתמש", help_text)


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
