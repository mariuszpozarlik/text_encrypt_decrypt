import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

class EncryptorApp:
    def __init__(self, master):
        self.master = master
        master.title("Text Encrypt/Decrypt (AES-GCM)")

        # Text input
        self.input_label = tk.Label(master, text="Input text:")
        self.input_label.pack()
        self.input_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, height=10)
        self.input_text.pack()

        # Password entry
        self.password_label = tk.Label(master, text="Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(master, show="*", width=40)
        self.password_entry.pack()

        # Buttons
        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(pady=5)

        # Output
        self.output_label = tk.Label(master, text="Output:")
        self.output_label.pack()
        self.output_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, height=10)
        self.output_text.pack()

    def encrypt(self):
        password = self.password_entry.get().encode()
        if len(password) < 16:
            messagebox.showerror("Error", "Password must be at least 16 bytes (characters) long")
            return

        text = self.input_text.get("1.0", tk.END).strip().encode()
        key = password[:32].ljust(32, b'0')
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, text, None)
        data = base64.b64encode(nonce + ciphertext).decode()
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, data)

    def decrypt(self):
        password = self.password_entry.get().encode()
        if len(password) < 16:
            messagebox.showerror("Error", "Password must be at least 16 bytes (characters) long")
            return

        data = self.input_text.get("1.0", tk.END).strip()
        try:
            raw = base64.b64decode(data)
            nonce, ciphertext = raw[:12], raw[12:]
            key = password[:32].ljust(32, b'0')
            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None).decode()
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptorApp(root)
    root.mainloop()
