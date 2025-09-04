import os
import sqlite3
import bcrypt
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path

# -------------------------
# Config / Paths
# -------------------------
BASE_DIR = Path.cwd()
DB_PATH = BASE_DIR / "users.db"
MASTER_KEY_FILE = BASE_DIR / "master.key"

# -------------------------
# Key management
# -------------------------
def load_or_create_master_key():
    if not MASTER_KEY_FILE.exists():
        key = AESGCM.generate_key(bit_length=256)
        MASTER_KEY_FILE.write_bytes(key)
        try:
            os.chmod(MASTER_KEY_FILE, 0o600)
        except Exception:
            pass
    else:
        key = MASTER_KEY_FILE.read_bytes()
    if len(key) != 32:
        raise ValueError("master.key must be 32 bytes")
    return key

MASTER_KEY = load_or_create_master_key()

# -------------------------
# Database helpers
# -------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            email_enc BLOB,
            nonce BLOB
        )
    """)
    conn.commit()
    conn.close()

def add_user(username: str, password_plain: str, email_plain: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    salt = bcrypt.gensalt()
    pw_hash = bcrypt.hashpw(password_plain.encode('utf-8'), salt)
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12)
    email_enc = aesgcm.encrypt(nonce, (email_plain or "").encode('utf-8'), None)
    try:
        c.execute(
            "INSERT INTO users (username, password_hash, email_enc, nonce) VALUES (?, ?, ?, ?)",
            (username, pw_hash, email_enc, nonce)
        )
        conn.commit()
        success = True
        msg = "User created."
    except sqlite3.IntegrityError:
        success = False
        msg = "Username already exists."
    conn.close()
    return success, msg

def authenticate_user(username: str, password_plain: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False, "No such user."
    user_id, pw_hash = row
    if bcrypt.checkpw(password_plain.encode('utf-8'), pw_hash):
        return True, user_id
    else:
        return False, "Incorrect password."

def get_user_sensitive(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT email_enc, nonce, username FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    email_enc, nonce, username = row
    aesgcm = AESGCM(MASTER_KEY)
    try:
        email = aesgcm.decrypt(nonce, email_enc, None).decode('utf-8')
    except Exception:
        email = "[decryption error]"
    return {"email": email, "username": username}

def change_password(user_id: int, new_password_plain: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    salt = bcrypt.gensalt()
    pw_hash = bcrypt.hashpw(new_password_plain.encode('utf-8'), salt)
    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, user_id))
    conn.commit()
    conn.close()
    return True

def delete_account(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return True

# -------------------------
# UI Helpers and Styles
# -------------------------
LARGE_FONT = ("Segoe UI", 14, "bold")
MED_FONT = ("Segoe UI", 10)
SMALL_FONT = ("Segoe UI", 9)

def create_styles():
    style = ttk.Style()
    # Use a built-in theme then tweak
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("TFrame", background="#f6f8fb")
    style.configure("Header.TLabel", background="#2b3742", foreground="white", font=LARGE_FONT)
    style.configure("SubHeader.TLabel", background="#f6f8fb", foreground="#333333", font=("Segoe UI", 11))
    style.configure("TButton", relief="flat", padding=8, font=MED_FONT)
    style.map("TButton", background=[("active", "#1f6feb")])
    style.configure("Primary.TButton", background="#2b7cff", foreground="white", font=MED_FONT, padding=8)
    style.configure("Danger.TButton", background="#e03b3b", foreground="white", font=MED_FONT, padding=8)
    style.configure("Card.TFrame", background="white", relief="flat")
    return style

# Small utility for rounded-rectangle like buttons using canvas (for visual flair)
class RoundedButton(tk.Canvas):
    def __init__(self, master, text="", command=None, width=160, height=36, radius=12, bg="#2b7cff", fg="white", font=MED_FONT, **kwargs):
        super().__init__(master, width=width, height=height, highlightthickness=0, bg="white", **kwargs)
        self.command = command
        self.radius = radius
        self.bg = bg
        self.fg = fg
        self.text = text
        self.font = font
        self.width = width
        self.height = height
        self._draw()
        self.bind("<Button-1>", lambda e: self._on_click())
        self.bind("<Enter>", lambda e: self.configure(cursor="hand2"))
        self.bind("<Leave>", lambda e: self.configure(cursor=""))

    def _draw(self):
        r = self.radius
        w = self.width
        h = self.height
        # create rounded rectangle
        self.create_arc((0, 0, r * 2, r * 2), start=90, extent=90, fill=self.bg, outline=self.bg)
        self.create_arc((w - 2 * r, 0, w, r * 2), start=0, extent=90, fill=self.bg, outline=self.bg)
        self.create_arc((0, h - 2 * r, 2 * r, h), start=180, extent=90, fill=self.bg, outline=self.bg)
        self.create_arc((w - 2 * r, h - 2 * r, w, h), start=270, extent=90, fill=self.bg, outline=self.bg)
        self.create_rectangle((r, 0, w - r, h), fill=self.bg, outline=self.bg)
        self.create_rectangle((0, r, w, h - r), fill=self.bg, outline=self.bg)
        self.create_text(w / 2, h / 2, text=self.text, fill=self.fg, font=self.font)

    def _on_click(self):
        if callable(self.command):
            self.command()

# -------------------------
# Main Application UI
# -------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AuroraAuth — Secure Login")
        self.geometry("720x480")
        self.minsize(700, 420)
        self.configure(bg="#f6f8fb")
        create_styles()
        self.style = ttk.Style()
        self.current_user_id = None

        # Layout: left panel (info/branding) and right panel (card area)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=2)
        self.rowconfigure(0, weight=1)

        self.left_frame = ttk.Frame(self, style="TFrame")
        self.left_frame.grid(row=0, column=0, sticky="nsew", padx=(30, 10), pady=30)
        self.right_frame = ttk.Frame(self, style="TFrame")
        self.right_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 30), pady=30)

        self._build_left()
        self._build_right_login_card()

    def _build_left(self):
        # Decorative header with gradient-like canvas
        canvas = tk.Canvas(self.left_frame, width=220, height=120, highlightthickness=0, bg="white")
        canvas.pack(pady=(0, 20))
        # draw simple gradient bars
        for i, color in enumerate(["#2b7cff", "#6ea8ff", "#b3d4ff"]):
            canvas.create_rectangle(0, 120 - (i+1)*36, 220, 120 - i*36, fill=color, outline=color)
        # Logo circle
        canvas.create_oval(14, 14, 74, 74, fill="#ffffff", outline="")
        canvas.create_text(44, 44, text="A", font=("Segoe UI", 20, "bold"), fill="#2b7cff")

        ttk.Label(self.left_frame, text="AuroraAuth", style="Header.TLabel").pack(anchor="w")
        ttk.Label(self.left_frame, text="A compact, stylish demo of secure auth\nwith AES-256 and bcrypt.", style="SubHeader.TLabel", wraplength=240).pack(anchor="w", pady=(10, 20))
        # Feature bullets
        feat = [
            "• Secure password hashing (bcrypt)",
            "• AES-256-GCM encrypted fields",
            "• Lightweight SQLite storage",
            "• Future: TOTP 2FA & OAuth 2.0"
        ]
        for f in feat:
            ttk.Label(self.left_frame, text=f, style="SubHeader.TLabel").pack(anchor="w", pady=2)

        # Quick action buttons
        btn_frame = ttk.Frame(self.left_frame, style="TFrame")
        btn_frame.pack(anchor="w", pady=(20, 0))
        btn_register = RoundedButton(btn_frame, text="Register", command=self._switch_to_register, width=140)
        btn_register.grid(row=0, column=0, padx=4, pady=4)
        btn_help = RoundedButton(btn_frame, text="About", command=self._about, width=140, bg="#6c757d")
        btn_help.grid(row=1, column=0, padx=4, pady=6)

    def _build_right_login_card(self):
        # clear right frame
        for w in self.right_frame.winfo_children():
            w.destroy()
        card = ttk.Frame(self.right_frame, style="Card.TFrame", padding=20)
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="Sign in to AuroraAuth", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(0, 10))

        # username
        ttk.Label(card, text="Username", font=MED_FONT).pack(anchor="w", pady=(8, 0))
        self.login_username = ttk.Entry(card, font=MED_FONT)
        self.login_username.pack(fill="x", pady=6)

        # password
        ttk.Label(card, text="Password", font=MED_FONT).pack(anchor="w", pady=(8, 0))
        self.login_password = ttk.Entry(card, font=MED_FONT, show="*")
        self.login_password.pack(fill="x", pady=6)

        # actions
        action_frame = ttk.Frame(card)
        action_frame.pack(fill="x", pady=(12, 6))
        btn_login = RoundedButton(action_frame, text="Sign In", command=self._do_login, width=160)
        btn_login.grid(row=0, column=0, padx=(0, 10))
        btn_to_register = ttk.Button(action_frame, text="Create account", command=self._switch_to_register, style="TButton")
        btn_to_register.grid(row=0, column=1, sticky="e")

        # spacer and foot
        ttk.Label(card, text=" ", style="SubHeader.TLabel").pack()
        ttk.Separator(card).pack(fill="x", pady=8)
        small = ttk.Label(card, text="Running in VM — key saved locally (master.key)", font=SMALL_FONT)
        small.pack(anchor="w")

    def _build_right_register_card(self):
        # clear right frame
        for w in self.right_frame.winfo_children():
            w.destroy()
        card = ttk.Frame(self.right_frame, style="Card.TFrame", padding=18)
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="Create an account", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(0, 10))

        ttk.Label(card, text="Username", font=MED_FONT).pack(anchor="w", pady=(6, 0))
        self.reg_username = ttk.Entry(card, font=MED_FONT)
        self.reg_username.pack(fill="x", pady=6)

        ttk.Label(card, text="Password", font=MED_FONT).pack(anchor="w", pady=(6, 0))
        self.reg_password = ttk.Entry(card, font=MED_FONT, show="*")
        self.reg_password.pack(fill="x", pady=6)

        ttk.Label(card, text="Email (optional)", font=MED_FONT).pack(anchor="w", pady=(6, 0))
        self.reg_email = ttk.Entry(card, font=MED_FONT)
        self.reg_email.pack(fill="x", pady=6)

        btn_frame = ttk.Frame(card)
        btn_frame.pack(fill="x", pady=(12, 6))
        btn_create = RoundedButton(btn_frame, text="Create Account", command=self._do_register, width=180)
        btn_create.grid(row=0, column=0, padx=(0, 8))
        btn_cancel = ttk.Button(btn_frame, text="Cancel", command=self._build_right_login_card)
        btn_cancel.grid(row=0, column=1, sticky="e")

        ttk.Label(card, text="Password strength: Use a long unique password", font=SMALL_FONT).pack(anchor="w", pady=(10, 0))

    def _build_right_dashboard(self):
        # clear right frame
        for w in self.right_frame.winfo_children():
            w.destroy()
        user = get_user_sensitive(self.current_user_id)
        username = user.get("username", "[user]") if user else "[user]"
        email = user.get("email", "[no-email]") if user else "[no-email]"

        card = ttk.Frame(self.right_frame, style="Card.TFrame", padding=18)
        card.pack(fill="both", expand=True)

        ttk.Label(card, text=f"Welcome, {username}", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(0, 8))
        ttk.Label(card, text=f"Email (decrypted): {email}", font=MED_FONT).pack(anchor="w", pady=(0, 12))

        btn_frame = ttk.Frame(card)
        btn_frame.pack(fill="x", pady=(6, 12))
        btn_change = ttk.Button(btn_frame, text="Change Password", command=self._action_change_password)
        btn_change.grid(row=0, column=0, padx=(0, 8))
        btn_delete = ttk.Button(btn_frame, text="Delete Account", command=self._action_delete_account, style="Danger.TButton")
        btn_delete.grid(row=0, column=1, padx=(8, 0))
        btn_logout = ttk.Button(card, text="Logout", command=self._do_logout)
        btn_logout.pack(anchor="w", pady=(8, 0))

        ttk.Separator(card).pack(fill="x", pady=12)
        ttk.Label(card, text="Account actions and info", font=SMALL_FONT).pack(anchor="w")

    # -------------------------
    # Actions
    # -------------------------
    def _switch_to_register(self):
        self._build_right_register_card()

    def _about(self):
        messagebox.showinfo("About", "AuroraAuth demo\nbcrypt + AES-256-GCM\nTOTP & OAuth planned.")

    def _do_register(self):
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        email = self.reg_email.get().strip()
        if not username or not password:
            messagebox.showerror("Validation", "Username and password are required.")
            return
        ok, msg = add_user(username, password, email)
        if ok:
            messagebox.showinfo("Success", "Account created. You may sign in.")
            self._build_right_login_card()
        else:
            messagebox.showerror("Error", msg)

    def _do_login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get()
        if not username or not password:
            messagebox.showerror("Validation", "Enter username and password.")
            return
        ok, result = authenticate_user(username, password)
        if ok:
            self.current_user_id = result
            self._build_right_dashboard()
            messagebox.showinfo("Welcome", f"Logged in as {username}")
            # clear fields
            self.login_username.delete(0, tk.END)
            self.login_password.delete(0, tk.END)
        else:
            messagebox.showerror("Error", result)

    def _action_change_password(self):
        new_pw = simpledialog.askstring("Change Password", "Enter new password:", show="*")
        if not new_pw:
            return
        change_password(self.current_user_id, new_pw)
        messagebox.showinfo("Success", "Password changed successfully.")

    def _action_delete_account(self):
        confirm = messagebox.askyesno("Delete", "Are you sure? This will remove your account.")
        if not confirm:
            return
        delete_account(self.current_user_id)
        messagebox.showinfo("Deleted", "Your account has been removed.")
        self.current_user_id = None
        self._build_right_login_card()

    def _do_logout(self):
        self.current_user_id = None
        messagebox.showinfo("Logged out", "You have been logged out.")
        self._build_right_login_card()

# -------------------------
# Entrypoint
# -------------------------
def main():
    init_db()
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
