# Tugas-1/crypto_algorithms/rc4_encryptor.py
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA1
import time

def rc4_encrypt_bytes(plaintext_bytes: bytes, key: str):
    start_time = time.perf_counter()
    # RC4 key can be variable length; derive fixed-length key via SHA1 (simple)
    key_bytes = key.encode('utf-8')
    k = SHA1.new(key_bytes).digest()  # 20 bytes
    cipher = ARC4.new(k)
    ciphertext = cipher.encrypt(plaintext_bytes)
    return ciphertext, time.perf_counter() - start_time

def rc4_decrypt_bytes(ciphertext_bytes: bytes, key: str):
    start_time = time.perf_counter()
    key_bytes = key.encode('utf-8')
    k = SHA1.new(key_bytes).digest()
    cipher = ARC4.new(k)
    plaintext = cipher.decrypt(ciphertext_bytes)
    return plaintext, time.perf_counter() - start_time
