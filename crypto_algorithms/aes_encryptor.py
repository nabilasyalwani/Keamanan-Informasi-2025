# Tugas-1/crypto_algorithms/aes_encryptor.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import time

def aes_encrypt_bytes(plaintext_bytes: bytes, key: str):
    start_time = time.perf_counter()
    key_bytes = key.encode('utf-8')
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes for AES.")
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    return ciphertext, time.perf_counter() - start_time

def aes_decrypt_bytes(ciphertext_bytes: bytes, key: str):
    start_time = time.perf_counter()
    key_bytes = key.encode('utf-8')
    iv = ciphertext_bytes[:16]
    ct = ciphertext_bytes[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct), AES.block_size)
    return plaintext, time.perf_counter() - start_time
