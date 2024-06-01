import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
import os
import re

def encrypt_image(input_image_path, output_image_path, password):
    salt = os.urandom(16)
    key = PBKDF2(password, salt, 32, count=1000000)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(input_image_path, 'rb') as f:
        plaintext = f.read()

    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    with open(output_image_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)

def decrypt_image(input_image_path, output_image_path, password):
    try:
        with open(input_image_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            ciphertext = f.read()

        key = PBKDF2(password, salt, 32, count=1000000)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        unpadded_data = unpad(decrypted_data, AES.block_size)

        with open(output_image_path, 'wb') as f:
            f.write(unpadded_data)

        show_post_action_interface("Decryption successful!")
    except (ValueError, KeyError):
        messagebox.showerror("Error", "The password is incorrect or the file is corrupted.")

def verify_password_strength(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def get_strong_password():
    password = password_entry.get()
    if verify_password_strength(password):
        return password
    else:
        messagebox.showerror("Error", "Password is not strong enough. Please enter a stronger password.")
        return None

def browse_file(entry_widget):
    file_path = filedialog.askopenfilename()
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, file_path)

def save_file(entry_widget):
    file_path = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[("JPEG files", "*.jpg"), ("All files", "*.*")])
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, file_path)

def encrypt_action():
    input_image_path = input_image_entry.get()
    output_image_path = output_image_entry.get()
    password = get_strong_password()
    if password:
        encrypt_image(input_image_path, output_image_path, password)
        show_post_action_interface("Encryption successful!")

def decrypt_action():
    input_image_path = decrypt_image_entry.get()
    output_image_path = save_decrypted_image_entry.get()
    password = password_entry.get()
    decrypt_image(input_image_path, output_image_path, password)

def show_post_action_interface(message):
    for widget in app.winfo_children():
        widget.destroy()
    
    message_label = tk.Label(app, text=message, font=("Arial", 12))
    message_label.pack(pady=20)

    button_frame = tk.Frame(app)
    button_frame.pack(pady=20)

    back_button = tk.Button(button_frame, text="Back to Home", command=show_welcome_interface, width=20)
    back_button.grid(row=0, column=0, padx=10, pady=10)

    close_button = tk.Button(button_frame, text="Close", command=app.quit, width=20)
    close_button.grid(row=0, column=1, padx=10, pady=10)

def show_encrypt_interface():
    for widget in app.winfo_children():
        widget.destroy()
    create_encrypt_interface()

def show_decrypt_interface():
    for widget in app.winfo_children():
        widget.destroy()
    create_decrypt_interface()

def show_welcome_interface():
    for widget in app.winfo_children():
        widget.destroy()
    create_welcome_interface()

def create_welcome_interface():
    welcome_label = tk.Label(app, text="Image Encryption/Decryption Project", font=("Arial", 16))
    welcome_label.pack(pady=20)

    credits_label = tk.Label(app, text="Developed by Khoubaib Bourbia, Islem Chouyakh, and Maha Jdidi", font=("Arial", 10))
    credits_label.pack(pady=5)

    choice_frame = tk.Frame(app)
    choice_frame.pack(pady=20)

    encrypt_button = tk.Button(choice_frame, text="Encrypt", command=show_encrypt_interface, width=20)
    encrypt_button.grid(row=0, column=0, padx=10, pady=10)

    decrypt_button = tk.Button(choice_frame, text="Decrypt", command=show_decrypt_interface, width=20)
    decrypt_button.grid(row=0, column=1, padx=10, pady=10)

def create_encrypt_interface():
    password_label = tk.Label(app, text="Enter Encrypt/Decrypt Password:")
    password_label.pack(pady=5)

    global password_entry
    password_entry = tk.Entry(app, show="*", width=30)
    password_entry.pack(pady=5)

    encrypt_frame = tk.Frame(app)
    encrypt_frame.pack(pady=5)

    input_image_label = tk.Label(encrypt_frame, text="Image to Encrypt:")
    input_image_label.grid(row=0, column=0, padx=5, pady=5)

    global input_image_entry
    input_image_entry = tk.Entry(encrypt_frame, width=30)
    input_image_entry.grid(row=0, column=1, padx=5, pady=5)

    browse_encrypt_button = tk.Button(encrypt_frame, text="Browse", command=lambda: browse_file(input_image_entry))
    browse_encrypt_button.grid(row=0, column=2, padx=5, pady=5)

    output_image_label = tk.Label(encrypt_frame, text="Save Encrypted Image As:")
    output_image_label.grid(row=1, column=0, padx=5, pady=5)

    global output_image_entry
    output_image_entry = tk.Entry(encrypt_frame, width=30)
    output_image_entry.grid(row=1, column=1, padx=5, pady=5)

    save_encrypt_button = tk.Button(encrypt_frame, text="Browse", command=lambda: save_file(output_image_entry))
    save_encrypt_button.grid(row=1, column=2, padx=5, pady=5)

    encrypt_button = tk.Button(app, text="Encrypt", command=encrypt_action)
    encrypt_button.pack(pady=10)

def create_decrypt_interface():
    password_label = tk.Label(app, text="Enter Encrypt/Decrypt Password:")
    password_label.pack(pady=5)

    global password_entry
    password_entry = tk.Entry(app, show="*", width=30)
    password_entry.pack(pady=5)

    decrypt_frame = tk.Frame(app)
    decrypt_frame.pack(pady=5)

    decrypt_image_label = tk.Label(decrypt_frame, text="Encrypted Image to Decrypt:")
    decrypt_image_label.grid(row=0, column=0, padx=5, pady=5)

    global decrypt_image_entry
    decrypt_image_entry = tk.Entry(decrypt_frame, width=30)
    decrypt_image_entry.grid(row=0, column=1, padx=5, pady=5)

    browse_decrypt_button = tk.Button(decrypt_frame, text="Browse", command=lambda: browse_file(decrypt_image_entry))
    browse_decrypt_button.grid(row=0, column=2, padx=5, pady=5)

    save_decrypted_image_label = tk.Label(decrypt_frame, text="Save Decrypted Image As:")
    save_decrypted_image_label.grid(row=1, column=0, padx=5, pady=5)

    global save_decrypted_image_entry
    save_decrypted_image_entry = tk.Entry(decrypt_frame, width=30)
    save_decrypted_image_entry.grid(row=1, column=1, padx=5, pady=5)

    save_decrypted_button = tk.Button(decrypt_frame, text="Browse", command=lambda: save_file(save_decrypted_image_entry))
    save_decrypted_button.grid(row=1, column=2, padx=5, pady=5)

    decrypt_button = tk.Button(app, text="Decrypt", command=decrypt_action)
    decrypt_button.pack(pady=10)

app = tk.Tk()
app.title("Image Encryption")
app.geometry("500x400")

create_welcome_interface()

app.mainloop()