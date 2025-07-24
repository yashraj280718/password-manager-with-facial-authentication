import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import cv2
import face_recognition
import numpy as np
import sqlite3
import os
from cryptography.fernet import Fernet
import pyautogui
import string
import random
import threading
from flask import Flask, request, jsonify

class PasswordManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SecurePass Manager")
        self.root.geometry("800x600")
        self.current_frame = None
        self.db = DatabaseHandler()
        self.current_user = None
        self.key = self.generate_encryption_key()
        self.cipher = Fernet(self.key)
        self.pending_approval = None  # For browser autofill
        self.start_server()
        self.show_welcome_screen()
        
    def generate_encryption_key(self):
        if not os.path.exists("secret.key"):
            key = Fernet.generate_key()
            with open("secret.key", "wb") as key_file:
                key_file.write(key)
        return open("secret.key", "rb").read()

    def show_frame(self, frame):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = frame
        self.current_frame.pack(fill=tk.BOTH, expand=True)

    def show_welcome_screen(self):
        self.current_user = None
        frame = tk.Frame(self.root)
        tk.Label(frame, text="Welcome to SecurePass", font=("Arial", 24)).pack(pady=50)
        ttk.Button(frame, text="Register", command=self.show_register_screen, style="Accent.TButton").pack(pady=10)
        ttk.Button(frame, text="Login", command=self.show_login_screen, style="Accent.TButton").pack(pady=10)
        self.show_frame(frame)

    def show_register_screen(self):
        frame = tk.Frame(self.root)
        tk.Label(frame, text="Registration", font=("Arial", 18)).pack(pady=20)
        self.register_username = ttk.Entry(frame)
        ttk.Label(frame, text="Username:").pack()
        self.register_username.pack()
        ttk.Button(frame, text="Capture Face", command=self.capture_face).pack(pady=10)
        ttk.Button(frame, text="Register", command=self.register_user).pack(pady=5)
        ttk.Button(frame, text="Back", command=self.show_welcome_screen).pack()
        self.show_frame(frame)

    def capture_face(self):
        cap = cv2.VideoCapture(0)
        messagebox.showinfo("Info", "Look at the camera and press OK to capture your face.")
        ret, frame = cap.read()
        if ret:
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            face_encodings = face_recognition.face_encodings(rgb_frame)
            if face_encodings:
                self.face_encoding = face_encodings[0]
                messagebox.showinfo("Success", "Face captured successfully!")
            else:
                messagebox.showerror("Error", "No face detected. Please try again.")
        else:
            messagebox.showerror("Error", "Failed to access webcam.")
        cap.release()

    def register_user(self):
        username = self.register_username.get()
        if not (username and hasattr(self, 'face_encoding')):
            messagebox.showerror("Error", "All fields are required and face must be captured.")
            return
        if self.db.user_exists(username):
            messagebox.showerror("Error", "Username already exists. Please choose another.")
            return
        self.db.create_user(username, self.face_encoding.tobytes())
        messagebox.showinfo("Success", "Registration successful! Please login.")
        self.show_login_screen()

    def show_login_screen(self):
        frame = tk.Frame(self.root)
        tk.Label(frame, text="Login", font=("Arial", 18)).pack(pady=20)
        self.login_username = ttk.Entry(frame)
        ttk.Label(frame, text="Username:").pack()
        self.login_username.pack()
        ttk.Button(frame, text="Login", command=self.login_user).pack(pady=10)
        ttk.Button(frame, text="Back", command=self.show_welcome_screen).pack()
        self.show_frame(frame)

    def login_user(self):
        username = self.login_username.get()
        if not username:
            messagebox.showerror("Error", "Username is required")
            return
        cursor = self.db.conn.execute("SELECT face_encoding FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            messagebox.showerror("Error", "User not found")
            return
        stored_face_encoding = user[0]
        cap = cv2.VideoCapture(0)
        messagebox.showinfo("Info", "Look at the camera for face verification.")
        ret, frame = cap.read()
        cap.release()
        if not ret:
            messagebox.showerror("Error", "Failed to access webcam")
            return
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_encodings = face_recognition.face_encodings(rgb_frame)
        if not face_encodings:
            messagebox.showerror("Error", "No face detected. Please try again.")
            return
        login_face_encoding = face_encodings[0]
        stored_face_encoding_np = np.frombuffer(stored_face_encoding, dtype=np.float64)
        stored_face_encoding_np = stored_face_encoding_np.reshape((128,))
        matches = face_recognition.compare_faces([stored_face_encoding_np], login_face_encoding)
        if matches[0]:
            messagebox.showinfo("Success", "Login successful!")
            self.current_user = username
            self.show_dashboard()
        else:
            messagebox.showerror("Error", "Face does not match. Access denied.")

    def show_dashboard(self):
        frame = tk.Frame(self.root)
        tk.Label(frame, text=f"Dashboard for {self.current_user}", font=("Arial", 24)).pack(pady=20)
        ttk.Button(frame, text="Add Password", command=self.show_add_password).pack(pady=10)
        ttk.Button(frame, text="View Passwords", command=self.show_view_passwords).pack(pady=10)
        ttk.Button(frame, text="Logout", command=self.show_welcome_screen).pack(pady=10)
        self.show_frame(frame)

    def show_add_password(self):
        frame = tk.Frame(self.root)
        tk.Label(frame, text="Add New Password", font=("Arial", 18)).pack(pady=20)
        self.site_entry = ttk.Entry(frame)
        self.username_entry = ttk.Entry(frame)
        self.password_entry = ttk.Entry(frame, show="*")
        ttk.Label(frame, text="Site/App:").pack(pady=(0,2))
        self.site_entry.pack(pady=(0,8), padx=10, fill=tk.X)
        ttk.Label(frame, text="Username/Email:").pack(pady=(0,2))
        self.username_entry.pack(pady=(0,8), padx=10, fill=tk.X)
        ttk.Label(frame, text="Password:").pack(pady=(0,2))
        self.password_entry.pack(pady=(0,2), padx=10, fill=tk.X)
        pw_frame = tk.Frame(frame)
        pw_frame.pack(pady=(0,8), padx=10, fill=tk.X)
        ttk.Button(pw_frame, text="Generate Password", command=self.generate_password).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(pw_frame, text="Copy", command=self.copy_password).pack(side=tk.LEFT)
        self.strength_label = ttk.Label(frame, text="Strength: ")
        self.strength_label.pack(pady=(0,8), padx=10, anchor='w')
        self.password_entry.bind('<KeyRelease>', self.update_strength)
        ttk.Button(frame, text="Save", command=self.save_password).pack(pady=10)
        ttk.Button(frame, text="Back", command=self.show_dashboard).pack()
        self.show_frame(frame)

    def generate_password(self, length=16):
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.SystemRandom().choice(chars) for _ in range(length))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

    def copy_password(self):
        pw = self.password_entry.get()
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    def update_strength(self, event=None):
        pw = self.password_entry.get()
        score = self.password_strength(pw)
        if score >= 4:
            txt = "Strong"
        elif score == 3:
            txt = "Medium"
        elif score == 2:
            txt = "Weak"
        else:
            txt = "Very Weak"
        self.strength_label.config(text=f"Strength: {txt}")

    def password_strength(self, pw):
        score = 0
        if len(pw) >= 8:
            score += 1
        if any(c.islower() for c in pw):
            score += 1
        if any(c.isupper() for c in pw):
            score += 1
        if any(c.isdigit() for c in pw):
            score += 1
        if any(c in string.punctuation for c in pw):
            score += 1
        return score

    def save_password(self):
        site = self.site_entry.get()
        uname = self.username_entry.get()
        pw = self.password_entry.get()
        if not (site and uname and pw):
            messagebox.showerror("Error", "All fields are required.")
            return
        encrypted_pw = self.cipher.encrypt(pw.encode())
        self.db.add_password(self.current_user, site, uname, encrypted_pw)
        messagebox.showinfo("Success", "Password saved successfully!")
        self.show_dashboard()

    def show_view_passwords(self):
        frame = tk.Frame(self.root)
        tk.Label(frame, text="Saved Passwords", font=("Arial", 18)).pack(pady=20)
        passwords = self.db.get_passwords(self.current_user)
        if not passwords:
            tk.Label(frame, text="No passwords saved yet.").pack(pady=10)
        else:
            tree = ttk.Treeview(frame, columns=("Site", "Username", "Password", "Autofill"), show="headings")
            tree.heading("Site", text="Site/App")
            tree.heading("Username", text="Username/Email")
            tree.heading("Password", text="Password")
            tree.heading("Autofill", text="Autofill")
            tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            for site, uname, enc_pw in passwords:
                try:
                    pw = self.cipher.decrypt(enc_pw).decode()
                except Exception:
                    pw = "Decryption Error"
                tree.insert("", tk.END, values=(site, uname, pw, "Autofill"))

            def on_tree_select(event):
                selected_item = tree.selection()
                if selected_item:
                    item = tree.item(selected_item)
                    site, uname, pw, _ = item['values']
                    self.autofill_credentials(uname, pw)

            tree.bind('<Double-1>', on_tree_select)
            tk.Label(frame, text="Double-click a row to autofill credentials into the current form.").pack(pady=5)
            ttk.Button(frame, text="Copy Selected Password", command=lambda: self.copy_selected_password(tree)).pack(pady=5)
        ttk.Button(frame, text="Back", command=self.show_dashboard).pack(pady=10)
        self.show_frame(frame)

    def copy_selected_password(self, tree):
        selected_item = tree.selection()
        if selected_item:
            item = tree.item(selected_item)
            pw = item['values'][2]
            self.root.clipboard_clear()
            self.root.clipboard_append(pw)
            messagebox.showinfo("Copied", "Password copied to clipboard.")

    def autofill_credentials(self, username, password):
        messagebox.showinfo("Autofill", "Switch to your login form and click OK to autofill.")
        pyautogui.write(str(username))
        pyautogui.press('tab')
        pyautogui.write(str(password))

    def start_server(self):
        app = Flask(__name__)
        manager = self

        @app.route('/get_credentials', methods=['POST'])
        def get_credentials():
            data = request.json
            site = data.get('site')
            if not manager.current_user:
                return jsonify({'error': 'Not authenticated'}), 403
            creds = manager.db.get_passwords(manager.current_user)
            for s, uname, enc_pw in creds:
                try:
                    pw = manager.cipher.decrypt(enc_pw).decode()
                except Exception:
                    pw = None
                if s == site:
                    # Ask user for approval
                    manager.pending_approval = {'site': s, 'username': uname, 'password': pw}
                    approved = manager.ask_approval(site, uname)
                    if approved:
                        return jsonify({'username': uname, 'password': pw})
                    else:
                        return jsonify({'error': 'User denied'}), 403
            return jsonify({'error': 'No credentials found'}), 404

        def run():
            app.run(port=5005, threaded=True, debug=False)

        threading.Thread(target=run, daemon=True).start()

    def ask_approval(self, site, username):
        result = tk.BooleanVar()
        def approve():
            result.set(True)
            popup.destroy()
        def deny():
            result.set(False)
            popup.destroy()
        popup = tk.Toplevel(self.root)
        popup.title("Approve Autofill Request")
        tk.Label(popup, text=f"Allow autofill for site: {site}\nUsername: {username}?", font=("Arial", 12)).pack(padx=20, pady=20)
        ttk.Button(popup, text="Approve", command=approve).pack(side=tk.LEFT, padx=10, pady=10)
        ttk.Button(popup, text="Deny", command=deny).pack(side=tk.RIGHT, padx=10, pady=10)
        popup.grab_set()
        self.root.wait_variable(result)
        return result.get()

class DatabaseHandler:
    def __init__(self):
        self.conn = sqlite3.connect('passman.db')
        self.create_tables()

    def create_tables(self):
        self.conn.execute('''CREATE TABLE IF NOT EXISTS users
                         (username TEXT PRIMARY KEY,
                         face_encoding BLOB)''')
        self.conn.execute('''CREATE TABLE IF NOT EXISTS passwords
                         (owner TEXT,
                          site TEXT,
                          uname TEXT,
                          password BLOB,
                          FOREIGN KEY(owner) REFERENCES users(username))''')

    def user_exists(self, username):
        cursor = self.conn.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return cursor.fetchone() is not None

    def create_user(self, username, face_encoding):
        self.conn.execute("INSERT INTO users VALUES (?, ?)",
                         (username, face_encoding))
        self.conn.commit()

    def add_password(self, owner, site, uname, password):
        self.conn.execute("INSERT INTO passwords VALUES (?, ?, ?, ?)",
                         (owner, site, uname, password))
        self.conn.commit()

    def get_passwords(self, owner):
        cursor = self.conn.execute("SELECT site, uname, password FROM passwords WHERE owner = ?", (owner,))
        return cursor.fetchall()

# Initialize application
if __name__ == "__main__":
    app = PasswordManager()
    style = ttk.Style()
    style.configure("Accent.TButton", font=("Arial", 12), padding=10)
    app.root.mainloop()
