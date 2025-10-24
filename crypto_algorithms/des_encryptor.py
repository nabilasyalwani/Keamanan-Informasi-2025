# Tugas-1/crypto_algorithms/des_encryptor.py
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import time

def des_encrypt_bytes(plaintext_bytes: bytes, key: str):
    start_time = time.time()
    key_bytes = key.encode('utf-8')
    if len(key_bytes) != 8:
        raise ValueError("DES key must be exactly 8 bytes.")
    iv = get_random_bytes(8)
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(pad(plaintext_bytes, DES.block_size))
    return ciphertext, time.time() - start_time

def des_decrypt_bytes(ciphertext_bytes: bytes, key: str):
    start_time = time.time()
    key_bytes = key.encode('utf-8')
    iv = ciphertext_bytes[:8]
    ct = ciphertext_bytes[8:]
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct), DES.block_size)
    return plaintext, time.time() - start_time
