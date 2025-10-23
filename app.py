from flask import Flask, render_template, request, send_from_directory, flash, redirect, url_for
import os
from crypto_algorithms.aes_encryptor import aes_encrypt, aes_decrypt
from crypto_algorithms.des_encryptor import des_encrypt, des_decrypt
from crypto_algorithms.rc4_encryptor import rc4_encrypt, rc4_decrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ===== Folder Konfigurasi =====
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted_files'
DECRYPTED_FOLDER = 'decrypted_files'

for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)


# ===== Fungsi Utama =====
def encrypt_file(filepath, key, algo):
    with open(filepath, 'rb') as f:
        data = f.read()

    if algo == 'AES':
        encrypted = aes_encrypt(data, key)
    elif algo == 'DES':
        encrypted = des_encrypt(data, key)
    elif algo == 'RC4':
        encrypted = rc4_encrypt(data, key)
    else:
        raise ValueError("Algoritma tidak dikenal")

    filename = os.path.basename(filepath)
    output_path = os.path.join(ENCRYPTED_FOLDER, f"{algo}_encrypted_{filename}")
    with open(output_path, 'wb') as f:
        f.write(encrypted)
    return output_path


def decrypt_file(filepath, key, algo):
    with open(filepath, 'rb') as f:
        encrypted = f.read()

    if algo == 'AES':
        decrypted = aes_decrypt(encrypted, key)
    elif algo == 'DES':
        decrypted = des_decrypt(encrypted, key)
    elif algo == 'RC4':
        decrypted = rc4_decrypt(encrypted, key)
    else:
        raise ValueError("Algoritma tidak dikenal")

    filename = os.path.basename(filepath)
    output_path = os.path.join(DECRYPTED_FOLDER, f"{algo}_decrypted_{filename}")
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    return output_path


# ===== Routing =====
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/', methods=['POST'])
def process_file():
    file = request.files['file']
    key = request.form['key']
    algo = request.form['method']
    operation = request.form['operation']

    if not file or not key or not algo:
        flash("Semua input harus diisi!")
        return redirect(url_for('index'))

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    try:
        if operation == 'encrypt':
            result_path = encrypt_file(filepath, key, algo)
            flash(f"File berhasil dienkripsi menggunakan {algo}.")
            folder = 'encrypted_files'
        elif operation == 'decrypt':
            result_path = decrypt_file(filepath, key, algo)
            flash(f"File berhasil didekripsi menggunakan {algo}.")
            folder = 'decrypted_files'
        else:
            raise ValueError("Operasi tidak valid.")

        filename = os.path.basename(result_path)
        return render_template('index.html', download_file=filename, folder=folder)

    except Exception as e:
        flash(f"Terjadi kesalahan: {e}")
        return redirect(url_for('index'))


@app.route('/download/<folder>/<filename>')
def download(folder, filename):
    return send_from_directory(folder, filename, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
