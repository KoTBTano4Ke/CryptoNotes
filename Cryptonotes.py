import tkinter as tk
from tkinter import messagebox, simpledialog
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# Encryption methods
def caesar_cipher_encrypt(text, shift):
    encrypted = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)

def base64_encrypt(text):
    return base64.b64encode(text.encode()).decode()

def base64_decrypt(ciphertext):
    return base64.b64decode(ciphertext.encode()).decode()

def reverse_encrypt(text):
    return text[::-1]

def reverse_decrypt(text):
    return text[::-1]

def xor_encrypt(text, key):
    encrypted = ''.join(chr(ord(c) ^ key) for c in text)
    return base64.b64encode(encrypted.encode()).decode()

def xor_decrypt(ciphertext, key):
    decrypted = base64.b64decode(ciphertext.encode()).decode()
    return ''.join(chr(ord(c) ^ key) for c in decrypted)

rsa_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
rsa_public_key = rsa_key.public_key()

def rsa_encrypt(text):
    ciphertext = rsa_public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(ciphertext):
    plaintext = rsa_key.decrypt(
        base64.b64decode(ciphertext.encode()),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

fernet_key = Fernet.generate_key()
fernet_cipher = Fernet(fernet_key)

def fernet_encrypt(text):
    return fernet_cipher.encrypt(text.encode()).decode()

def fernet_decrypt(ciphertext):
    return fernet_cipher.decrypt(ciphertext.encode()).decode()

def atbash_encrypt(text):
    encrypted = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                encrypted += chr(122 - (ord(char) - 97))
            else:
                encrypted += chr(90 - (ord(char) - 65))
        else:
            encrypted += char
    return encrypted

def atbash_decrypt(text):
    return atbash_encrypt(text)

# GUI Application
class EncryptedNotesApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Encrypted Notes")

        self.notes = {}  # Dictionary to store notes: {title: (encrypted_note, encryption_method, password)}

        self.label = tk.Label(master, text="Encrypted Notes", font=("Helvetica", 16))
        self.label.pack(pady=10)

        self.notes_listbox = tk.Listbox(master)
        self.notes_listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.notes_listbox.bind('<<ListboxSelect>>', self.on_note_select)

        self.add_button = tk.Button(master, text="Add Note", command=self.add_note)
        self.add_button.pack(pady=5)

        self.view_encrypted_button = tk.Button(master, text="View Encrypted Note", command=self.view_encrypted_note)
        self.view_encrypted_button.pack(pady=5)

        self.view_button = tk.Button(master, text="View Decrypted Note", command=self.view_note)
        self.view_button.pack(pady=5)

    def add_note(self):
        title = simpledialog.askstring("Add Note", "Enter note title:")
        if not title:
            return

        note = simpledialog.askstring("Add Note", "Enter your note:")
        if not note:
            return

        method = simpledialog.askstring(
            "Add Note", 
            "Enter encryption method (caesar/rsa/base64/reverse/xor/fernet/atbash):"
        )
        if method not in ["caesar", "rsa", "base64", "reverse", "xor", "fernet", "atbash"]:
            messagebox.showerror("Error", "Invalid encryption method.")
            return

        password = simpledialog.askstring("Add Note", "Enter password:")
        if not password:
            return

        if method == "caesar":
            encrypted_note = caesar_cipher_encrypt(note, shift=3)
        elif method == "rsa":
            encrypted_note = rsa_encrypt(note)
        elif method == "base64":
            encrypted_note = base64_encrypt(note)
        elif method == "reverse":
            encrypted_note = reverse_encrypt(note)
        elif method == "xor":
            key = ord(password[0])
            encrypted_note = xor_encrypt(note, key)
        elif method == "fernet":
            encrypted_note = fernet_encrypt(note)
        elif method == "atbash":
            encrypted_note = atbash_encrypt(note)

        self.notes[title] = (encrypted_note, method, password)
        self.notes_listbox.insert(tk.END, title)
        messagebox.showinfo("Success", "Note added and encrypted successfully!")

    def view_encrypted_note(self):
        selected = self.notes_listbox.curselection()
        if not selected:
            messagebox.showwarning("Warning", "No note selected.")
            return

        title = self.notes_listbox.get(selected)
        encrypted_note, method, password = self.notes[title]

        messagebox.showinfo("Encrypted Note", f"Title: {title}\n\nEncrypted Note: {encrypted_note}\n\nMethod: {method}")

    def view_note(self):
        selected = self.notes_listbox.curselection()
        if not selected:
            messagebox.showwarning("Warning", "No note selected.")
            return

        title = self.notes_listbox.get(selected)
        encrypted_note, method, password = self.notes[title]

        input_password = simpledialog.askstring("View Note", "Enter password:")
        if input_password != password:
            messagebox.showerror("Error", "Incorrect password.")
            return

        if method == "caesar":
            decrypted_note = caesar_cipher_decrypt(encrypted_note, shift=3)
        elif method == "rsa":
            decrypted_note = rsa_decrypt(encrypted_note)
        elif method == "base64":
            decrypted_note = base64_decrypt(encrypted_note)
        elif method == "reverse":
            decrypted_note = reverse_decrypt(encrypted_note)
        elif method == "xor":
            key = ord(password[0])
            decrypted_note = xor_decrypt(encrypted_note, key)
        elif method == "fernet":
            decrypted_note = fernet_decrypt(encrypted_note)
        elif method == "atbash":
            decrypted_note = atbash_decrypt(encrypted_note)

        messagebox.showinfo("Decrypted Note", f"Title: {title}\n\nNote: {decrypted_note}\n\nMethod: {method}")

    def on_note_select(self, event):
        pass  # Placeholder for any future features

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptedNotesApp(root)
    root.mainloop()
