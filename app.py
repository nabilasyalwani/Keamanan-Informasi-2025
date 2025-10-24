from flask import Flask, render_template, request, send_from_directory, flash, redirect, url_for, session, send_file, abort
import os, io, time
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from crypto_algorithms.aes_encryptor import aes_encrypt_bytes, aes_decrypt_bytes
from crypto_algorithms.des_encryptor import des_encrypt_bytes, des_decrypt_bytes
from crypto_algorithms.rc4_encryptor import rc4_encrypt_bytes, rc4_decrypt_bytes

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',       
    'database': 'fanspakbas'
}

# -------------------------
# Folder setup
# -------------------------
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted_files'
DECRYPTED_FOLDER = 'decrypted_files'

for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

app = Flask(__name__)
app.secret_key = "supersecretkey55"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # max 50 MB

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

# -------------------------
# Auth routes
# -------------------------
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash("Isi username dan password.")
            return redirect(url_for('register'))
        pw_hash = generate_password_hash(password)
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (username, password_hash) VALUES (%s,%s)", (username, pw_hash))
            conn.commit()
            flash("Registrasi berhasil. Silakan login.")
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash("Username sudah dipakai.")
            return redirect(url_for('register'))
        finally:
            cur.close(); conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        conn = get_db(); cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        cur.close(); conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash("Login berhasil.")
            return redirect(url_for('index'))
        else:
            flash("Login gagal.")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))

# helper: require login
def login_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash("Silakan login terlebih dahulu.")
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

# -------------------------
# Main index / upload
# -------------------------
@app.route('/', methods=['GET','POST'])
@login_required
def index():
    if request.method == 'POST':
        file = request.files.get('file')
        key = request.form.get('key', '')
        algo = request.form.get('method')
        operation = request.form.get('operation')

        if not file or not key or not algo:
            flash("Semua input harus diisi!")
            return redirect(url_for('index'))

        filename = secure_filename(file.filename)
        raw_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(raw_path)

        with open(raw_path, 'rb') as f:
            data = f.read()

        # pilih algoritma
        if algo == 'AES':
            enc_fn, dec_fn = aes_encrypt_bytes, aes_decrypt_bytes
        elif algo == 'DES':
            enc_fn, dec_fn = des_encrypt_bytes, des_decrypt_bytes
        elif algo == 'RC4':
            enc_fn, dec_fn = rc4_encrypt_bytes, rc4_decrypt_bytes
        else:
            flash("Algoritma tidak dikenal.")
            return redirect(url_for('index'))

        conn = get_db(); cur = conn.cursor()
        try:
            if operation == 'encrypt':
                ciphertext, enc_time = enc_fn(data, key)
                size = len(ciphertext)

                # Rename hasil enkripsi jadi [nama_file_asli]_enc.ext
                base_name, ext = os.path.splitext(filename)
                stored_name = f"{base_name}_enc{ext}"
                encrypted_path = os.path.join(ENCRYPTED_FOLDER, stored_name)

                with open(encrypted_path, 'wb') as ef:
                    ef.write(ciphertext)

                # Simpan metadata + ciphertext ke database
                cur.execute("""
                    INSERT INTO files (owner_id, filename, stored_filename, algorithm, ciphertext, ciphertext_size, enc_time)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                """, (session['user_id'], filename, stored_name, algo, ciphertext, size, enc_time))
                conn.commit()

                flash(f"File berhasil dienkripsi dengan {algo}. "
                    f"Disimpan sebagai {stored_name} (enc_time={enc_time:.4f}s, size={size} bytes)")

            elif operation == 'decrypt':
                plaintext, dec_time = dec_fn(data, key)

                # Rename hasil dekripsi jadi [nama_file_asli]_dec.ext
                base_name, ext = os.path.splitext(filename)
                dec_name = f"{base_name}_dec{ext}"
                decrypted_path = os.path.join(DECRYPTED_FOLDER, dec_name)

                with open(decrypted_path, 'wb') as df:
                    df.write(plaintext)

                flash(f"File berhasil didekripsi (dec_time={dec_time:.4f}s). "
                    f"Hasil tersimpan di {decrypted_path}")
                return send_file(decrypted_path, as_attachment=True)

            else:
                flash("Operasi tidak valid.")

        except Exception as e:
            flash(f"Terjadi kesalahan: {e}")
        finally:
            cur.close(); conn.close()
            try:
                os.remove(raw_path)
            except:
                pass

        return redirect(url_for('index'))

    # GET: tampilkan file milik user dan yang dibagikan
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM files WHERE owner_id=%s ORDER BY created_at DESC", (session['user_id'],))
    owned = cur.fetchall()
    cur.execute("""SELECT f.* FROM files f
                   JOIN shares s ON s.file_id=f.id
                   WHERE s.shared_with_user_id=%s ORDER BY f.created_at DESC""", (session['user_id'],))
    shared = cur.fetchall()
    cur.close(); conn.close()
    return render_template('index.html', owned=owned, shared=shared)

# -------------------------
# Download / decrypt from DB (authorized)
# -------------------------
@app.route('/do_decrypt', methods=['POST'])
@login_required
def do_decrypt():
    file_id = int(request.form['file_id'])
    key = request.form['key']

    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM files WHERE id=%s", (file_id,))
    f = cur.fetchone()
    cur.close(); conn.close()

    if not f:
        flash("File tidak ditemukan.")
        return redirect(url_for('index'))

    ciphertext = f['ciphertext']
    algo = f['algorithm']

    try:
        # pilih algoritma dekripsi
        if algo == 'AES':
            plaintext, dec_time = aes_decrypt_bytes(ciphertext, key)
        elif algo == 'DES':
            plaintext, dec_time = des_decrypt_bytes(ciphertext, key)
        elif algo == 'RC4':
            plaintext, dec_time = rc4_decrypt_bytes(ciphertext, key)
        else:
            flash("Algoritma tidak dikenal.")
            return redirect(url_for('index'))

        # Gunakan nama asli, tapi ubah jadi _dec.ext
        base_name, ext = os.path.splitext(f['filename'])
        dec_name = f"{base_name}_dec{ext}"
        dec_path = os.path.join(DECRYPTED_FOLDER, dec_name)

        # simpan hasil dekripsi ke file
        with open(dec_path, 'wb') as df:
            df.write(plaintext)

        # update waktu dekripsi di DB
        conn = get_db(); cur = conn.cursor()
        cur.execute("UPDATE files SET dec_time=%s WHERE id=%s", (dec_time, file_id))
        conn.commit()
        cur.close(); conn.close()

        flash(f"File '{f['filename']}' berhasil didekripsi (dec_time={dec_time:.4f}s).")
        return send_file(dec_path, as_attachment=True)

    except Exception as e:
        flash(f"Gagal didekripsi: {e}")
        return redirect(url_for('index'))

# -------------------------
# Performance page
# -------------------------
@app.route('/performance')
@login_required
def performance():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT f.*, u.username AS owner_name FROM files f JOIN users u ON f.owner_id=u.id ORDER BY f.created_at DESC")
    rows = cur.fetchall()
    cur.close(); conn.close()
    return render_template('performance.html', rows=rows)

if __name__ == '__main__':
    app.run(debug=True)
