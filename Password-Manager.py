import sqlite3
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import os
import tkinter as tk
from tkinter import messagebox, simpledialog

# Path to the EULA signed flag
EULA_FILE = "eula_signed.txt"

# Generate and store the key securely
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Load the secret key from the file
def load_key():
    return open("secret.key", "rb").read()

# Encrypt the password
def encrypt_password(password):
    key = load_key()
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password

# Decrypt the password
def decrypt_password(encrypted_password):
    key = load_key()
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password).decode()
    return decrypted_password

# Create database for storing passwords
def create_db():
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site TEXT,
        encrypted_password BLOB,
        created_at TEXT,
        expiry_days INTEGER
    )
    """)
    conn.commit()
    conn.close()

# Add password to the database
def add_password(site, password, expiry_days):
    # Check for duplicate site names (case-insensitive)
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE LOWER(site) = ?", (site.lower(),))
    if cursor.fetchone():
        conn.close()
        return False  # Duplicate site found
    encrypted_password = encrypt_password(password)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO passwords (site, encrypted_password, created_at, expiry_days) VALUES (?, ?, ?, ?)",
                   (site, encrypted_password, created_at, expiry_days))
    conn.commit()
    conn.close()
    return True

# Retrieve password from the database
def get_password(site):
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, encrypted_password, created_at, expiry_days FROM passwords WHERE LOWER(site) = ?", (site.lower(),))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result
    else:
        return None

# Update password in the database
def update_password(site, new_password):
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM passwords WHERE LOWER(site) = ?", (site.lower(),))
    result = cursor.fetchone()
    if result:
        password_id = result[0]
        encrypted_password = encrypt_password(new_password)
        cursor.execute("UPDATE passwords SET encrypted_password = ? WHERE id = ?", (encrypted_password, password_id))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

# Check password expiry
def check_password_expiry(site):
    result = get_password(site)
    if result:
        _, _, created_at, expiry_days = result
        created_at = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
        if expiry_days == 0:
            return False  # Password never expires
        expiry_date = created_at + timedelta(days=expiry_days)
        if datetime.now() > expiry_date:
            return True
    return False

# Prompt user to change expired password
def prompt_password_change(site):
    if check_password_expiry(site):
        result = messagebox.askyesno("Password Expired", f"The password for {site} has expired. Do you want to change it?")
        if result:
            new_password = simpledialog.askstring("New Password", "Enter the new password:")
            if new_password:
                if update_password(site, new_password):
                    messagebox.showinfo("Success", f"Password for {site} updated successfully.")
                else:
                    messagebox.showwarning("Error", "Failed to update the password.")
            else:
                messagebox.showwarning("Invalid Input", "Password cannot be empty.")
        else:
            messagebox.showinfo("No Change", "Password not changed.")
    else:
        messagebox.showinfo("Password Valid", f"Password for {site} is still valid.")

# Format the site input to autofill "www." and ".com"
def format_site_input(site):
    site = site.strip().lower()
    if not site.startswith("www."):
        site = "www." + site
    if not site.endswith(".com"):
        site = site + ".com"
    return site

# Function to check if the user has already signed the EULA
def check_eula_signed():
    return os.path.exists(EULA_FILE)

# Function to mark the EULA as signed
def mark_eula_signed():
    with open(EULA_FILE, 'w') as f:
        f.write("User has accepted the EULA.")

# EULA popup
def show_eula_popup(root, callback):
    eula_text = """End User License Agreement (EULA)

    By using this software, you agree to the following terms and conditions:
    1. You will use the software for personal and non-commercial use only.
    2. You will not reverse engineer, decompile, or disassemble the software.
    3. The developer is not responsible for any damage caused by using this software.

    Please read and accept the terms to continue.
    """

    def accept_eula():
        mark_eula_signed()
        eula_window.destroy()  # Close the EULA window after accepting
        callback()

    eula_window = tk.Toplevel(root)
    eula_window.title("End User License Agreement (EULA)")
    
    title_label = tk.Label(eula_window, text="======================================================================\nWELCOME TO THE PASSWORD MANAGER\n======================================================================", font=("Helvetica", 12), anchor='center')
    title_label.pack(pady=5)

    

    description_label = tk.Label(eula_window, text="""8888888888888888888888888888888888888888888888888888888888888888888888\n8888888888888888888888888888888888888888888888888888888888888888888888\n8888888888888888888888888888888P""    ""9888888888888888888888888888888888\n8888888888888888888888P"88888P                    988888"9888888888888888888888888\n88888888888888888888888    "9888                      888P"    8888888888888888888888888\n8888888888888888888888888bo "9  d8o     o8b  P" od888888888888888888888888888\n888888888888888888888888888bob 98"     "8P dod88888888888888888888888888888\n888888888888888888888888888888       db       88888888888888888888888888888888\n888888888888888888888888888888888      88888888888888888888888888888888888\n88888888888888888888888888888P"9bo  odP"98888888888888888888888888888888\n88888888888888888888888888P" od88888888bo "98888888888888888888888888888\n8888888888888888888888888   d88888888888888b   888888888888888888888888888\n888888888888888888888888oo88888888888888888oo88888888888888888888888888\n88888888888888888888888888888888888888888888888888888888888888888888888""""", font=("Helvetica", 12), anchor='center')
    description_label.pack(pady=5)

    title_label = tk.Label(eula_window, text="======================================================================\nThis tool lets you safely secure and update passwords!\nProgram created by: Benjamin Barish\n======================================================================", font=("Helvetica", 12), anchor='center')
    

    title_label.pack(pady=5)


    # The rest of the EULA text will be left-aligned
    eula_label = tk.Label(eula_window, text=eula_text,font=("Helvetica", 12) , justify=tk.LEFT, anchor='w')  # Left justify most of the content
    eula_label.pack(padx=20, pady=20)
    
    accept_button = tk.Button(eula_window, text="Accept", command=accept_eula)
    accept_button.pack(pady=10)
    
    eula_window.mainloop()

# GUI Setup
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("400x400")

        # Add Site and Password
        self.site_label = tk.Label(root, text="Site Name:")
        self.site_label.pack()
        
        self.site_entry = tk.Entry(root)
        self.site_entry.pack()
        
        self.password_label = tk.Label(root, text="Password:")
        self.password_label.pack()
        
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()
        
        self.expiry_label = tk.Label(root, text="Password Expiry (Days or 0 for Never):")
        self.expiry_label.pack()
        
        self.expiry_entry = tk.Entry(root)
        self.expiry_entry.pack()
        
        self.add_button = tk.Button(root, text="Add Password", command=self.add_password)
        self.add_button.pack(pady=10)
        
        # Retrieve Password
        self.retrieve_button = tk.Button(root, text="Retrieve Password", command=self.retrieve_password)
        self.retrieve_button.pack(pady=10)
        
        # Check Password Expiry
        self.check_button = tk.Button(root, text="Check Expiry", command=self.check_expiry)
        self.check_button.pack(pady=10)
        
        # Change Password
        self.change_button = tk.Button(root, text="Change Password", command=self.change_password)
        self.change_button.pack(pady=10)
        
        # Exit Button
        self.exit_button = tk.Button(root, text="Exit", command=self.exit_program)
        self.exit_button.pack(pady=10)

    def add_password(self):
        site = self.site_entry.get().strip()
        password = self.password_entry.get().strip()
        expiry_days = self.expiry_entry.get().strip()

        if site and password and expiry_days:
            site = format_site_input(site)
            try:
                expiry_days = int(expiry_days)
                if expiry_days < 0:
                    messagebox.showwarning("Invalid Input", "Expiry days cannot be negative.")
                    return
                # Add password to DB
                if add_password(site, password, expiry_days):
                    messagebox.showinfo("Success", f"Password for {site} added successfully.")
                    self.site_entry.delete(0, tk.END)
                    self.password_entry.delete(0, tk.END)
                    self.expiry_entry.delete(0, tk.END)
                else:
                    messagebox.showwarning("Duplicate Site", "A password for this site already exists.")
            except ValueError:
                messagebox.showwarning("Invalid Input", "Expiry days must be a valid number.")
        else:
            messagebox.showwarning("Invalid Input", "Site, password, and expiry days cannot be empty.")

    def retrieve_password(self):
        site = self.site_entry.get().strip()
        if site:
            site = format_site_input(site)
            result = get_password(site)
            if result:
                password, created_at, expiry_days = result[1], result[2], result[3]
                decrypted_password = decrypt_password(password)
                messagebox.showinfo("Password Retrieved", f"Password for {site} is: {decrypted_password}")
                if check_password_expiry(site):
                    messagebox.showinfo("Password Expired", f"The password for {site} has expired.")
            else:
                messagebox.showwarning("Not Found", f"No password found for {site}.")
        else:
            messagebox.showwarning("Invalid Input", "Site cannot be empty.")
    
    def check_expiry(self):
        site = self.site_entry.get().strip()
        if site:
            site = format_site_input(site)
            prompt_password_change(site)
        else:
            messagebox.showwarning("Invalid Input", "Site cannot be empty.")
    
    def change_password(self):
        site = self.site_entry.get().strip()
        if site:
            site = format_site_input(site)
            new_password = simpledialog.askstring("New Password", "Enter the new password:")
            if new_password:
                if update_password(site, new_password):
                    messagebox.showinfo("Success", f"Password for {site} updated successfully.")
                else:
                    messagebox.showwarning("Error", "Failed to update the password.")
            else:
                messagebox.showwarning("Invalid Input", "Password cannot be empty.")
        else:
            messagebox.showwarning("Invalid Input", "Site cannot be empty.")

    def exit_program(self):
        self.root.quit()

# Run application
def run():
    create_db()
    root = tk.Tk()

    # Check if the EULA is signed
    if not check_eula_signed():
        show_eula_popup(root, lambda: PasswordManagerApp(root))  # Show EULA first

    else:
        app = PasswordManagerApp(root)
        root.mainloop()

if __name__ == "__main__":
    run()
