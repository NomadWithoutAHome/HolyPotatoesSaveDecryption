import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
import codecs
import json

# GUI setup
root = tk.Tk()
root.title("File Encryption/Decryption")
root.geometry("400x200")


class CommonAPI:
    KEY = "e1n6c3dy4n9k2ey5"  # Encryption key

    @staticmethod
    def encrypt(to_encrypt: str) -> str:
        cleaned_input = CommonAPI._clean_input(to_encrypt)

        key_bytes = CommonAPI.KEY.encode('utf-8')
        to_encrypt_bytes = cleaned_input.encode('utf-8')

        # Pad the input data using PKCS7
        padded_data = pad(to_encrypt_bytes, AES.block_size)

        rijndael_cipher = AES.new(key_bytes, AES.MODE_ECB)
        encrypted_bytes = rijndael_cipher.encrypt(padded_data)

        encrypted_text = base64.b64encode(encrypted_bytes).decode('utf-8')
        return encrypted_text

    @staticmethod
    def decrypt(to_decrypt: str) -> str:
        key_bytes = CommonAPI.KEY.encode('utf-8')
        to_decrypt_bytes = base64.b64decode(to_decrypt)

        rijndael_cipher = AES.new(key_bytes, AES.MODE_ECB)
        decrypted_bytes = rijndael_cipher.decrypt(to_decrypt_bytes)

        # Unpad the decrypted data
        unpadded_data = unpad(decrypted_bytes, AES.block_size)

        decrypted_text = unpadded_data.decode('utf-8')
        return decrypted_text

    @staticmethod
    def read_content(file_path: str) -> str:
        encodings = ["utf-8", "latin-1", "utf-16"]
        text = ""
        for encoding in encodings:
            try:
                with codecs.open(file_path, 'r', encoding=encoding, errors='ignore') as file:
                    text = file.read()
                break
            except UnicodeDecodeError:
                continue

        return text

    @staticmethod
    def save_content(file_path: str, text: str) -> None:
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(text)
        except IOError as ex:
            raise IOError("Error saving content: " + str(ex))

    @staticmethod
    def _clean_input(to_clean: str) -> str:
        to_clean = to_clean.strip("'")
        to_clean = to_clean.replace("''", "'")
        return to_clean


def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        decrypt_file(file_path)


def decrypt_file(file_path):
    # Read the content of the file
    text = CommonAPI.read_content(file_path)

    # Decrypt the content
    decrypted_text = CommonAPI.decrypt(text)

    # Save the decrypted content as JSON file
    json_file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
    if json_file_path:
        CommonAPI.save_content(json_file_path, decrypted_text)
        status_label.config(text="File decrypted and saved as JSON.")


def select_json_file():
    json_file_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
    if json_file_path:
        encrypt_file(json_file_path)


def encrypt_file(json_file_path):
    # Read the JSON file
    json_data = CommonAPI.read_content(json_file_path)

    # Encrypt the JSON data
    encrypted_text = CommonAPI.encrypt(json_data)

    # Save the encrypted content as text file
    text_file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if text_file_path:
        CommonAPI.save_content(text_file_path, encrypted_text)
        status_label.config(text="File encrypted and saved as text.")


# GUI elements
decrypt_button = tk.Button(root, text="Decrypt File", command=select_file)
decrypt_button.pack(pady=20)

encrypt_button = tk.Button(root, text="Encrypt File", command=select_json_file)
encrypt_button.pack(pady=10)

status_label = tk.Label(root, text="")
status_label.pack()

root.mainloop()