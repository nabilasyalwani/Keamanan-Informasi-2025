from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import base64
import time

def aes_encrypt(file_path, key):
    start_time = time.time()

    key_bytes = key.encode('utf-8')
    if len(key_bytes) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes.")

    # Generate IV untuk mode CBC
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    output_path = os.path.join("encrypted_files", f"AES_encrypted_{os.path.basename(file_path)}")
    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)  # Simpan IV di awal file

    end_time = time.time()
    encryption_time = end_time - start_time
    return output_path, encryption_time

def aes_decrypt(file_path, key):
    start_time = time.time()

    key_bytes = key.encode('utf-8')
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    output_path = os.path.join("decrypted_files", f"AES_decrypted_{os.path.basename(file_path)}")
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    end_time = time.time()
    decryption_time = end_time - start_time
    return output_path, decryption_time
