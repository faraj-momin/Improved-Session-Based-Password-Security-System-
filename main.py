import hashlib
import secrets
import time
import tkinter as tk
from tkinter import messagebox

# Database to store user credentials
user_database = {}

# Database to store active sessions
active_sessions = {}

# Function to generate salt
def generate_salt():
    return secrets.token_hex(8)

# Function to hash password with salt
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

# Function to create a new user
def create_user(username, password):
    if username not in user_database:
        salt = generate_salt()
        hashed_password = hash_password(password, salt)
        user_database[username] = {"password": hashed_password, "salt": salt}
        messagebox.showinfo("Success", "User created successfully!")
        return True
    else:
        messagebox.showerror("Error", "Username already exists!")
        return False

# Function to authenticate user
def authenticate(username, password):
    if username in user_database:
        stored_password = user_database[username]["password"]
        salt = user_database[username]["salt"]
        hashed_password = hash_password(password, salt)
        if hashed_password == stored_password:
            return True
    return False

# Function to change password
def change_password(username, old_password, new_password):
    if authenticate(username, old_password):
        salt = user_database[username]["salt"]
        hashed_password = hash_password(new_password, salt)
        user_database[username]["password"] = hashed_password
        messagebox.showinfo("Success", "Password changed successfully!")
        return True
    else:
        messagebox.showerror("Error", "Authentication failed. Password not changed.")
        return False

# Function to create a new session
def create_session(username):
    session_id = secrets.token_hex(16)
    active_sessions[session_id] = {"username": username, "timestamp": time.time()}
    return session_id

# Function to validate session
def validate_session(session_id):
    if session_id in active_sessions:
        session = active_sessions[session_id]
        # Check if session is expired (e.g., 1 hour)
        if time.time() - session["timestamp"] <= 3600:
            return True
        else:
            # Session expired, remove it from active sessions
            del active_sessions[session_id]
    return False

# Main GUI application
class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Improved Session Password-Based Security System")
        self.geometry("300x200")
        self.create_widgets()

    def create_widgets(self):
        self.label = tk.Label(self, text="Select an option:")
        self.label.pack()

        self.register_button = tk.Button(self, text="Register", command=self.register)
        self.register_button.pack()

        self.login_button = tk.Button(self, text="Login", command=self.login)
        self.login_button.pack()

        self.change_password_button = tk.Button(self, text="Change Password", command=self.change_password)
        self.change_password_button.pack()

        self.logout_button = tk.Button(self, text="Logout", command=self.logout)
        self.logout_button.pack()

        self.exit_button = tk.Button(self, text="Exit", command=self.destroy)
        self.exit_button.pack()

    def register(self):
        register_window = RegisterWindow(self)

    def login(self):
        login_window = LoginWindow(self)

    def change_password(self):
        change_password_window = ChangePasswordWindow(self)

    def logout(self):
        logout_window = LogoutWindow(self)

# Register window
class RegisterWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Register")
        self.geometry("200x150")
        self.master = master
        self.create_widgets()

    def create_widgets(self):
        self.username_label = tk.Label(self, text="Username:")
        self.username_label.pack()
        self.username_entry = tk.Entry(self)
        self.username_entry.pack()

        self.password_label = tk.Label(self, text="Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()

        self.register_button = tk.Button(self, text="Register", command=self.register)
        self.register_button.pack()

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            create_user(username, password)
            self.destroy()
        else:
            messagebox.showerror("Error", "Username and password cannot be empty.")

# Login window
class LoginWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Login")
        self.geometry("200x150")
        self.master = master
        self.create_widgets()

    def create_widgets(self):
        self.username_label = tk.Label(self, text="Username:")
        self.username_label.pack()
        self.username_entry = tk.Entry(self)
        self.username_entry.pack()

        self.password_label = tk.Label(self, text="Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()

        self.login_button = tk.Button(self, text="Login", command=self.login)
        self.login_button.pack()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            if authenticate(username, password):
                session_id = create_session(username)
                messagebox.showinfo("Success", f"Login successful. Session ID: {session_id}")
                self.destroy()
            else:
                messagebox.showerror("Error", "Authentication failed. Please try again.")
        else:
            messagebox.showerror("Error", "Username and password cannot be empty.")

# Change password window
class ChangePasswordWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Change Password")
        self.geometry("200x200")
        self.master = master
        self.create_widgets()

    def create_widgets(self):
        self.session_id_label = tk.Label(self, text="Session ID:")
        self.session_id_label.pack()
        self.session_id_entry = tk.Entry(self)
        self.session_id_entry.pack()

        self.old_password_label = tk.Label(self, text="Old Password:")
        self.old_password_label.pack()
        self.old_password_entry = tk.Entry(self, show="*")
        self.old_password_entry.pack()

        self.new_password_label = tk.Label(self, text="New Password:")
        self.new_password_label.pack()
        self.new_password_entry = tk.Entry(self, show="*")
        self.new_password_entry.pack()

        self.change_password_button = tk.Button(self, text="Change Password", command=self.change_password)
        self.change_password_button.pack()

    def change_password(self):
        session_id = self.session_id_entry.get()
        old_password = self.old_password_entry.get()
        new_password = self.new_password_entry.get()
        if session_id and old_password and new_password:
            if validate_session(session_id):
                username = active_sessions[session_id]["username"]
                change_password(username, old_password, new_password)
                self.destroy()
            else:
                messagebox.showerror("Error", "Session invalid or expired. Please login again")

# Logout window
class LogoutWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Logout")
        self.geometry("200x150")
        self.master = master
        self.create_widgets()

    def create_widgets(self):
        self.session_id_label = tk.Label(self, text="Session ID:")
        self.session_id_label.pack()
        self.session_id_entry = tk.Entry(self)
        self.session_id_entry.pack()

        self.logout_button = tk.Button(self, text="Logout", command=self.logout)
        self.logout_button.pack()

    def logout(self):
        session_id = self.session_id_entry.get()
        if session_id:
            if validate_session(session_id):
                del active_sessions[session_id]
                messagebox.showinfo("Success", "Logout successful.")
                self.destroy()
            else:
                messagebox.showerror("Error", "Session invalid or expired. Please log in again.")
        else:
            messagebox.showerror("Error", "Session ID cannot be empty.")

if __name__ == "__main__":
    app = Application()
    app.mainloop()
