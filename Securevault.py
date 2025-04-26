import os
import base64
import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
import tkinter.scrolledtext as scrolledtext
import pyperclip
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from PIL import Image, ImageTk


class SecureVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureVault - Advanced Encryption Suite")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)

        # Initialize theme and fonts
        self.initialize_theme()

        self.create_layout()

    def initialize_theme(self):
        """Initialize application theme and fonts."""
        self.theme = {
            'background': '#121212',
            'surface': '#1E1E1E',
            'primary': '#6200EE',
            'secondary': '#03DAC6',
            'error': '#CF6679',
            'text_primary': '#FFFFFF',
            'text_secondary': '#B0B0B0',
            'accent': '#BB86FC'
        }

        self.fonts = {
            'title': ('Roboto', 28, 'bold'),
            'subtitle': ('Roboto', 16),
            'body': ('Roboto', 14),
        }

    def create_layout(self):
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=BOTH, expand=YES)

        canvas = tk.Canvas(main_container)
        scrollbar = ttk.Scrollbar(main_container, orient=VERTICAL, command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.create_header(scrollable_frame)

        self.notebook = ttk.Notebook(scrollable_frame)
        self.notebook.pack(fill=BOTH, expand=YES, padx=20, pady=10)

        tabs = [
            ("🔤 Text/Hash", self.create_text_hash_encryption_tab),
            ("📁 File", self.create_file_encryption_tab),
            ("🖼️ Image", self.create_image_encryption_tab),
        ]

        for title, creator in tabs:
            tab = ttk.Frame(self.notebook)
            creator(tab)
            self.notebook.add(tab, text=title)

        self.create_footer(scrollable_frame)

    def create_header(self, parent):
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=X, pady=(10, 20))

        logo_label = ttk.Label(
            header_frame, 
            text="🔐 SecureVault", 
            font=self.fonts['title'],
            foreground=self.theme['accent']
        )
        logo_label.pack(side=LEFT, padx=(20, 10))

        subtitle_label = ttk.Label(
            header_frame, 
            text="Advanced Encryption Suite", 
            font=self.fonts['subtitle']
        )
        subtitle_label.pack(side=LEFT, pady=5)

    def create_footer(self, parent):
        footer_frame = ttk.Frame(parent)
        footer_frame.pack(fill=X, pady=(10, 10))

        version_label = ttk.Label(
            footer_frame, 
            text="v1.0", 
            font=self.fonts['body'],
            foreground=self.theme['secondary']
        )
        version_label.pack(side=LEFT, padx=20)

        love_label = ttk.Label(
            footer_frame, 
            text="Built with ❤️ and 🔒", 
            font=('Roboto', 8) 
        )
        love_label.pack(side=RIGHT, padx=70)

    def create_text_hash_encryption_tab(self, tab):
        container = ttk.Frame(tab)
        container.pack(fill=BOTH, expand=YES, padx=20, pady=20)

        # Input area
        input_label = ttk.Label(container, text="Enter Text or Hash", font=self.fonts['subtitle'])
        input_label.pack(anchor=W)

        self.text_input = scrolledtext.ScrolledText(container, height=8, font=self.fonts['body'])
        self.text_input.pack(fill=X, pady=(5, 10))

        # Passphrase Input
        passphrase_label = ttk.Label(container, text="Encryption Passphrase", font=self.fonts['subtitle'])
        passphrase_label.pack(anchor=W)

        self.text_passphrase = ttk.Entry(container, show='*', font=self.fonts['body'])
        self.text_passphrase.pack(fill=X, pady=(5, 10))

        # Buttons for Encryption/Decryption
        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=X, pady=10)

        ttk.Button(btn_frame, text="Encrypt", command=self.encrypt_text_or_hash, style='primary.TButton').pack(side=LEFT, padx=5, fill=X, expand=YES)
        ttk.Button(btn_frame, text="Decrypt", command=self.decrypt_input_text_or_hash, style='secondary.TButton').pack(side=LEFT, padx=5, fill=X, expand=YES)

        # Output area
        result_label = ttk.Label(container, text="Result", font=self.fonts['subtitle'])
        result_label.pack(anchor=W)

        self.text_result = scrolledtext.ScrolledText(container, height=8, font=self.fonts['body'])
        self.text_result.pack(fill=X, pady=(5, 10))
        self.text_result.bind("<Control-a>", self.select_all)

        result_btn_frame = ttk.Frame(container)
        result_btn_frame.pack(fill=X, pady=5)

        ttk.Button(result_btn_frame, text="📋 Copy", command=self.copy_result_text, style='info.TButton').pack(side=LEFT, padx=5, fill=X, expand=YES)
        ttk.Button(result_btn_frame, text="🗑️ Clear", command=self.clear_result_text, style='danger.TButton').pack(side=LEFT, padx=5, fill=X, expand=YES)

    def select_all(self, event):
        """Select all text in result area when Ctrl+A is pressed."""
        self.text_result.tag_add('sel', '1.0', 'end')
        return "break"

    def encrypt_text_or_hash(self):
        """Encrypt the provided text or hash."""
        message = self.text_input.get("1.0", tk.END).strip()
        passphrase = self.text_passphrase.get()

        if not message or not passphrase:
            messagebox.showerror("Error", "Message and passphrase are required")
            return
        
        try:
            # Generate key with salt
            salt = os.urandom(16)
            key = self.derive_key(passphrase, salt)

            # Encrypt the message
            f = Fernet(key)
            encrypted = f.encrypt(message.encode())

            # Combine salt and encrypted data
            encrypted_data = salt + encrypted

            # Encode the entire package
            encoded_result = base64.urlsafe_b64encode(encrypted_data).decode()

            # Clear result and update
            self.text_result.delete("1.0", tk.END)
            self.text_result.insert(tk.END, encoded_result)

            messagebox.showinfo("Success", "Text/Hash encrypted successfully!")
        
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_input_text_or_hash(self):
        """Decrypt the provided input text or hash."""
        input_text = self.text_input.get("1.0", tk.END).strip()  # Use upper input area for decryption
        passphrase = self.text_passphrase.get()

        if not input_text or not passphrase:
            messagebox.showerror("Error", "Encrypted text and passphrase are required")
            return

        try:
            # Decode the base64 encoded text
            decoded_data = base64.urlsafe_b64decode(input_text.encode())

            # Extract salt and encrypted message
            salt = decoded_data[:16]
            encrypted = decoded_data[16:]

            # Derive the key using the same salt
            key = self.derive_key(passphrase, salt)

            # Decrypt the message
            f = Fernet(key)

            try:
                decrypted = f.decrypt(encrypted).decode()
            except InvalidToken:
                messagebox.showwarning("Decryption Failed", "Invalid passphrase! Please check your encryption key.")
                return

            # Clear result and update with decrypted text
            self.text_result.delete("1.0", tk.END)
            self.text_result.insert(tk.END, decrypted)
            messagebox.showinfo("Success", "Text/Hash decrypted successfully!")

        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def derive_key(self, passphrase, salt):
        """Derive a secure encryption key."""
        if not passphrase:
            raise ValueError("Passphrase cannot be empty")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        return key

    def copy_result_text(self):
        """Copy the result text to the clipboard."""
        result_text = self.text_result.get("1.0", tk.END).strip()
        if result_text:
            pyperclip.copy(result_text)
            messagebox.showinfo("Copied", "Result text copied to clipboard!")
        else:
            messagebox.showwarning("Empty", "No result text to copy!")

    def clear_result_text(self):
        """Clear the result text area."""
        self.text_result.delete("1.0", tk.END)

    def create_file_encryption_tab(self, tab):
        """Create file encryption tab."""
        container = ttk.Frame(tab)
        container.pack(fill=BOTH, expand=YES, padx=20, pady=20)

        # File selection
        file_select_frame = ttk.Frame(container)
        file_select_frame.pack(fill=X, pady=10)

        self.selected_file_path = tk.StringVar(value="No file selected")
        ttk.Label(file_select_frame, textvariable=self.selected_file_path, font=self.fonts['body']).pack(side=LEFT)
        ttk.Button(file_select_frame, text="Browse", command=self.select_file, style='primary.TButton').pack(side=RIGHT)

        # Passphrase Input
        passphrase_label = ttk.Label(container, text="File Encryption Passphrase", font=self.fonts['subtitle'])
        passphrase_label.pack(anchor=W)

        self.file_passphrase = ttk.Entry(container, show='*', font=self.fonts['body'])
        self.file_passphrase.pack(fill=X, pady=(5, 10))

        # Encryption buttons
        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=X, pady=10)

        ttk.Button(btn_frame, text="Encrypt File", command=self.encrypt_file, style='primary.TButton').pack(side=LEFT, padx=5, fill=X, expand=YES)
        ttk.Button(btn_frame, text="Decrypt File", command=self.decrypt_file, style='secondary.TButton').pack(side=LEFT, padx=5, fill=X, expand=YES)

        # Result display
        self.file_result_var = tk.StringVar()
        result_label = ttk.Label(container, textvariable=self.file_result_var, font=self.fonts['body'])
        result_label.pack(fill=X, pady=10)

    def select_file(self):
        """Select a file for encryption."""
        filepath = filedialog.askopenfilename()
        if filepath:
            self.selected_file_path.set(os.path.basename(filepath))
            self.file_path = filepath

    def encrypt_file(self):
        """Encrypt the selected file."""
        filepath = getattr(self, 'file_path', None)
        passphrase = self.file_passphrase.get()

        if not filepath or not passphrase:
            messagebox.showerror("Error", "Select a file and enter a passphrase")
            return

        try:
            # Read file content
            with open(filepath, 'rb') as file:
                data = file.read()

            # Encrypt file content
            salt = os.urandom(16)
            key = self.derive_key(passphrase, salt)

            f = Fernet(key)
            encrypted = f.encrypt(data)

            encrypted_data = salt + encrypted

            # Save encrypted file
            save_path = filedialog.asksaveasfilename(defaultextension=".encrypted",
                                                      filetypes=[("Encrypted Files", "*.encrypted")])

            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(encrypted_data)

                self.file_result_var.set(f"File encrypted: {save_path}")
                messagebox.showinfo("Success", "File encrypted successfully!")

        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_file(self):
        """Decrypt the selected file."""
        filepath = getattr(self, 'file_path', None)
        passphrase = self.file_passphrase.get()

        if not filepath or not passphrase:
            messagebox.showerror("Error", "Select an encrypted file and enter a passphrase")
            return

        try:
            # Read encrypted file
            with open(filepath, 'rb') as file:
                data = file.read()

            # Extract salt and encrypted data
            salt = data[:16]
            encrypted = data[16:]

            # Derive key using salt
            key = self.derive_key(passphrase, salt)

            # Decrypt the file
            f = Fernet(key)
            decrypted = f.decrypt(encrypted)

            # Save decrypted file
            save_path = filedialog.asksaveasfilename(title="Save Decrypted File")

            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(decrypted)

                self.file_result_var.set(f"File decrypted: {save_path}")
                messagebox.showinfo("Success", "File decrypted successfully!")

        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def create_image_encryption_tab(self, tab):
        """Create image encryption tab."""
        container = ttk.Frame(tab)
        container.pack(fill=BOTH, expand=YES, padx=20, pady=20)

        self.image_preview = ttk.Label(container, text="Select an Image", style='primary.TLabel')
        self.image_preview.pack(fill=X, pady=10)

        file_select_frame = ttk.Frame(container)
        file_select_frame.pack(fill=X, pady=10)

        self.selected_image_path = tk.StringVar(value="No image selected")
        ttk.Label(file_select_frame, textvariable=self.selected_image_path, font=self.fonts['body']).pack(side=LEFT)
        ttk.Button(file_select_frame, text="Browse Image", command=self.select_image, style='primary.TButton').pack(side=RIGHT)

        passphrase_label = ttk.Label(container, text="Image Encryption Passphrase", font=self.fonts['subtitle'])
        passphrase_label.pack(anchor=W)

        self.image_passphrase = ttk.Entry(container, show='*', font=self.fonts['body'])
        self.image_passphrase.pack(fill=X, pady=(5, 10))

        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=X, pady=10)

        ttk.Button(btn_frame, text="Encrypt Image", command=self.encrypt_image, style='primary.TButton').pack(side=LEFT, padx=5, fill=X, expand=YES)
        ttk.Button(btn_frame, text="Decrypt Image", command=self.decrypt_image, style='secondary.TButton').pack(side=LEFT, padx=5, fill=X, expand=YES)

        self.image_result_var = tk.StringVar()
        result_label = ttk.Label(container, textvariable=self.image_result_var, font=self.fonts['body'])
        result_label.pack(fill=X, pady=10)

    def select_image(self):
        """Select an image for encryption."""
        filepath = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if filepath:
            self.selected_image_path.set(os.path.basename(filepath))
            self.image_path = filepath

            try:
                img = Image.open(filepath)
                img.thumbnail((300, 300))
                photo = ImageTk.PhotoImage(img)
                self.image_preview.configure(image=photo)
                self.image_preview.image = photo
            except Exception as e:
                messagebox.showwarning("Preview Error", f"Could not preview image: {str(e)}")

    def encrypt_image(self):
        """Encrypt the selected image."""
        filepath = getattr(self, 'image_path', None)
        passphrase = self.image_passphrase.get()

        if not filepath or not passphrase:
            messagebox.showerror("Error", "Select an image and enter a passphrase")
            return

        try:
            with open(filepath, 'rb') as file:
                data = file.read()

            salt = os.urandom(16)
            key = self.derive_key(passphrase, salt)

            f = Fernet(key)
            encrypted = f.encrypt(data)

            encrypted_data = salt + encrypted

            save_path = filedialog.asksaveasfilename(defaultextension=".encrypted",
                                                      filetypes=[("Encrypted Images", "*.encrypted")])

            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(encrypted_data)

                self.image_result_var.set(f"Image encrypted: {save_path}")
                messagebox.showinfo("Success", "Image encrypted successfully!")

        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_image(self):
        """Decrypt the selected image."""
        filepath = getattr(self, 'image_path', None)
        passphrase = self.image_passphrase.get()

        if not filepath or not passphrase:
            messagebox.showerror("Error", "Select an encrypted image and enter a passphrase")
            return

        try:
            with open(filepath, 'rb') as file:
                data = file.read()

            salt = data[:16]
            encrypted = data[16:]

            key = self.derive_key(passphrase, salt)

            f = Fernet(key)

            try:
                decrypted = f.decrypt(encrypted)
            except InvalidToken:
                messagebox.showwarning("Decryption Failed", "Invalid passphrase!")
                return

            save_path = filedialog.asksaveasfilename(title="Save Decrypted Image")

            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(decrypted)

                try:
                    img = Image.open(save_path)
                    img.thumbnail((300, 300))
                    photo = ImageTk.PhotoImage(img)
                    self.image_preview.configure(image=photo)
                    self.image_preview.image = photo
                except Exception as e:
                    messagebox.showwarning("Preview Error", f"Could not preview image: {str(e)}")

                self.image_result_var.set(f"Image decrypted: {save_path}")
                messagebox.showinfo("Success", "Image decrypted successfully!")

        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))


def main():
    """Application entry point."""
    root = ttk.Window(themename="darkly")
    app = SecureVaultApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()