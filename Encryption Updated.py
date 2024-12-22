import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from cryptography.fernet import Fernet
import string
import pandas as pd
import os

# Setup characters for Caesar Cipher
chars = " " + string.punctuation + string.digits + string.ascii_letters
chars = list(chars)

# Function to generate a key for Fernet encryption
def generate_key():
    key = Fernet.generate_key()
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key.decode())
    messagebox.showinfo("Generated Key", f"Generated Key: {key.decode()}")

# Function to add message to history
def add_to_history(operation, message, result, encryption_type, key):
    history_listbox.insert(tk.END, f"{operation}: {message} -> {result} (Type: {encryption_type}, Key: {key})")

# Function to encrypt a message using Fernet
def encrypt_message_key():
    key = key_entry.get().encode()
    message = message_entry.get()
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    encrypted_message_entry.delete(0, tk.END)
    encrypted_message_entry.insert(0, encrypted_message.decode())
    add_to_history("Encrypted", message, encrypted_message.decode(), "Fernet", key.decode())

# Function to decrypt a message using Fernet
def decrypt_message_key():
    key = key_entry.get().encode()
    encrypted_message = encrypted_message_entry.get().encode()
    fernet = Fernet(key)
    try:
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        decrypted_message_entry.delete(0, tk.END)
        decrypted_message_entry.insert(0, decrypted_message)
        add_to_history("Decrypted", encrypted_message.decode(), decrypted_message, "Fernet", key.decode())
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during decryption: {e}")

# Function to encrypt a message using Caesar Cipher
def encrypt_message_shift():
    try:
        shift = int(shift_entry.get())
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid number for the shift.")
        return
    
    plain_text = message_entry.get()
    cipher_text = ""
    
    for letter in plain_text:
        if letter in chars:
            index = chars.index(letter)
            cipher_text += chars[(index + shift) % len(chars)]
        else:
            cipher_text += letter
    
    encrypted_message_entry.delete(0, tk.END)
    encrypted_message_entry.insert(0, cipher_text)
    add_to_history("Encrypted", plain_text, cipher_text, "Caesar Cipher", f"Shift: {shift}")
    messagebox.showinfo("Encryption", f"Original message: {plain_text}\nEncrypted message: {cipher_text}")

# Function to decrypt a message using Caesar Cipher
def decrypt_message_shift():
    try:
        shift = int(shift_entry.get())
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid number for the shift.")
        return
    
    cipher_text = encrypted_message_entry.get()
    plain_text = ""
    
    for letter in cipher_text:
        if letter in chars:
            index = chars.index(letter)
            plain_text += chars[(index - shift) % len(chars)]
        else:
            plain_text += letter
    
    decrypted_message_entry.delete(0, tk.END)
    decrypted_message_entry.insert(0, plain_text)
    add_to_history("Decrypted", cipher_text, plain_text, "Caesar Cipher", f"Shift: {shift}")
    messagebox.showinfo("Decryption", f"Encrypted message: {cipher_text}\nOriginal message: {plain_text}")

# Function to switch to Fernet encryption UI
def use_key_encryption():
    clear_entries()
    key_frame.pack(pady=10)
    shift_frame.pack_forget()
    encrypt_button.config(command=encrypt_message_key)
    decrypt_button.config(command=decrypt_message_key)

# Function to switch to Caesar Cipher UI
def use_shift_encryption():
    clear_entries()
    key_frame.pack_forget()
    shift_frame.pack(pady=10)
    encrypt_button.config(command=encrypt_message_shift)
    decrypt_button.config(command=decrypt_message_shift)

# Function to clear all entries
def clear_entries():
    key_entry.delete(0, tk.END)
    message_entry.delete(0, tk.END)
    encrypted_message_entry.delete(0, tk.END)
    decrypted_message_entry.delete(0, tk.END)
    shift_entry.delete(0, tk.END)

# Function to export history to Excel file
def export_history():
    file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
    if file_path:
        history_data = list(history_listbox.get(0, tk.END))
        data = []
        for entry in history_data:
            parts = entry.split(": ", 1)
            operation = parts[0]
            message_result = parts[1].rsplit(" (Type: ", 1)
            message = message_result[0].split(" -> ", 1)[0]
            result = message_result[0].split(" -> ", 1)[1]
            encryption_type = message_result[1].split(", Key: ")[0]
            key = message_result[1].split(", Key: ")[1][:-1]
            data.append([operation, message, result, encryption_type, key])
        
        df = pd.DataFrame(data, columns=["Operation", "Message", "Result", "Encryption Type", "Key"])
        
        if os.path.exists(file_path):
            existing_df = pd.read_excel(file_path)
            df = pd.concat([existing_df, df], ignore_index=True)
        
        df.to_excel(file_path, index=False)
        messagebox.showinfo("Export History", f"History exported successfully to {file_path}")

# Create the main window
root = tk.Tk()
root.title("Encryption Methods")

# Choose encryption method frame
method_frame = tk.Frame(root)
method_frame.pack(pady=10)
tk.Label(method_frame, text="Choose encryption method:").pack(side=tk.LEFT)
tk.Button(method_frame, text="Encryption with Key", command=use_key_encryption).pack(side=tk.LEFT, padx=5)
tk.Button(method_frame, text="Caesar Cipher", command=use_shift_encryption).pack(side=tk.LEFT, padx=5)

# Key frame
key_frame = tk.Frame(root)
key_label = tk.Label(key_frame, text="Key:")
key_label.pack(side=tk.LEFT)
key_entry = tk.Entry(key_frame, width=50)
key_entry.pack(side=tk.LEFT)
generate_key_button = tk.Button(key_frame, text="Generate Key", command=generate_key)
generate_key_button.pack(side=tk.LEFT)

# Shift frame
shift_frame = tk.Frame(root)
shift_label = tk.Label(shift_frame, text="Enter number of shifts:")
shift_label.pack(side=tk.LEFT)
shift_entry = tk.Entry(shift_frame, width=10)
shift_entry.pack(side=tk.LEFT)

# Message frame
message_frame = tk.Frame(root)
message_frame.pack(pady=10)
message_label = tk.Label(message_frame, text="Message:")
message_label.pack(side=tk.LEFT)
message_entry = tk.Entry(message_frame, width=50)
message_entry.pack(side=tk.LEFT)

# Encrypt button
encrypt_button = tk.Button(root, text="Encrypt")
encrypt_button.pack(pady=5)

# Encrypted message frame
encrypted_message_frame = tk.Frame(root)
encrypted_message_frame.pack(pady=10)
encrypted_message_label = tk.Label(encrypted_message_frame, text="Encrypted Message:")
encrypted_message_label.pack(side=tk.LEFT)
encrypted_message_entry = tk.Entry(encrypted_message_frame, width=50)
encrypted_message_entry.pack(side=tk.LEFT)

# Decrypt button
decrypt_button = tk.Button(root, text="Decrypt")
decrypt_button.pack(pady=5)

# Decrypted message frame
decrypted_message_frame = tk.Frame(root)
decrypted_message_frame.pack(pady=10)
decrypted_message_label = tk.Label(decrypted_message_frame, text="Decrypted Message:")
decrypted_message_label.pack(side=tk.LEFT)
decrypted_message_entry = tk.Entry(decrypted_message_frame, width=50)
decrypted_message_entry.pack(side=tk.LEFT)

# History frame
history_frame = tk.Frame(root)
history_frame.pack(pady=10)
history_label = tk.Label(history_frame, text="History:")
history_label.pack(side=tk.TOP)
history_listbox = tk.Listbox(history_frame, width=80, height=10)
history_listbox.pack(side=tk.LEFT)
history_scrollbar = tk.Scrollbar(history_frame, orient=tk.VERTICAL, command=history_listbox.yview)
history_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
history_listbox.config(yscrollcommand=history_scrollbar.set)

# Export button
export_button = tk.Button(root, text="Export History", command=export_history)
export_button.pack(pady=5)

# Run the main loop
root.mainloop()
