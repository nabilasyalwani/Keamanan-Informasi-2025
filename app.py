from db import get_db
from flask import Flask, render_template, request, send_from_directory, flash, redirect, url_for, session, send_file, abort, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from crypto_algorithms.aes_encryptor import aes_encrypt_bytes, aes_decrypt_bytes
from crypto_algorithms.des_encryptor import des_encrypt_bytes, des_decrypt_bytes
from crypto_algorithms.rc4_encryptor import rc4_encrypt_bytes, rc4_decrypt_bytes
import os, io, time
import mysql.connector  

# -------------------------
# Folder setup
# -------------------------
ENCRYPTED_FOLDER = 'encrypted_files'
DECRYPTED_FOLDER = 'decrypted_files'

for folder in [ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

app = Flask(__name__)
app.secret_key = "supersecretkey55"
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # max 50 MB

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
            return redirect(url_for('upload_report'))
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
# Performance page
# -------------------------
@app.route('/performance')
@login_required
def performance():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    # Ambil semua data encrypted files dengan logs
    cur.execute("""
        SELECT 
            ef.id, ef.filename, ef.file_type, ef.algorithm, 
            ef.ciphertext_size, ef.enc_time, ef.created_at,
            u.username AS owner_name,
            l.duration as dec_time
        FROM encrypted_files ef 
        JOIN users u ON ef.owner_id=u.id 
        LEFT JOIN logs l ON ef.id=l.file_id AND l.operation='decrypt'
        ORDER BY ef.created_at DESC
    """)
    rows = cur.fetchall()
    comparison_data = {}
    
    for row in rows:
        algo = row['algorithm']
        ftype = row['file_type'] or 'other'
        
        if algo not in comparison_data:
            comparison_data[algo] = {}
        
        if ftype not in comparison_data[algo]:
            comparison_data[algo][ftype] = {
                'count': 0,
                'total_enc_time': 0,
                'total_dec_time': 0,
                'total_size': 0,
                'avg_enc_time': 0,
                'avg_dec_time': 0,
                'avg_size': 0
            }
        
        comparison_data[algo][ftype]['count'] += 1
        comparison_data[algo][ftype]['total_enc_time'] += (row['enc_time'] or 0) * 1000  # convert to ms
        comparison_data[algo][ftype]['total_dec_time'] += (row['dec_time'] or 0) * 1000  # convert to ms
        comparison_data[algo][ftype]['total_size'] += row['ciphertext_size'] or 0
    
    for algo in comparison_data:
        for ftype in comparison_data[algo]:
            count = comparison_data[algo][ftype]['count']
            if count > 0:
                comparison_data[algo][ftype]['avg_enc_time'] = comparison_data[algo][ftype]['total_enc_time'] / count
                comparison_data[algo][ftype]['avg_dec_time'] = comparison_data[algo][ftype]['total_dec_time'] / count if comparison_data[algo][ftype]['total_dec_time'] > 0 else 0
                comparison_data[algo][ftype]['avg_size'] = comparison_data[algo][ftype]['total_size'] / count
    
    cur.close(); conn.close()
    return render_template('performance.html', rows=rows, comparison_data=comparison_data)

# -------------------------
# Profile Page
# -------------------------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = None
    profile_data = None
    
    if 'user_id' in session:
        conn = get_db(); cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, username, profile_file_id FROM users WHERE id=%s", (session['user_id'],))
        user = cur.fetchone()
        # Jika user punya profile_file_id, ambil info file-nya
        if user and user['profile_file_id']:
            cur.execute("SELECT algorithm FROM encrypted_files WHERE id=%s", (user['profile_file_id'],))
            profile_data = cur.fetchone()
        cur.close(); conn.close()

    if request.method == 'POST':
        image = request.files.get('profile_image')
        if image and image.filename:
            filename = secure_filename(image.filename)
            base_name, ext = os.path.splitext(filename)
            file_type = 'image'
            algos = request.form.getlist('algorithms')  # values: AES, DES, RC4
            if not algos:
                flash('Pilih minimal satu algoritma.')
                return redirect(url_for('profile'))
            
            # Pastikan setiap algoritma memiliki key
            missing = [a for a in algos if not (request.form.get(f'key_{a}') or '').strip()]
            if missing:
                flash('Key wajib diisi untuk: ' + ', '.join(missing))
                return redirect(url_for('profile'))
            
            data = image.read()
            conn = get_db(); cur = conn.cursor()
            try:
                for a in algos:
                    timestamp = int(time.time() * 1000) # milliseconds      
                    
                    if a == 'AES':
                        enc_fn = aes_encrypt_bytes
                    elif a == 'DES':
                        enc_fn = des_encrypt_bytes
                    elif a == 'RC4':
                        enc_fn = rc4_encrypt_bytes
                    else:
                        flash(f"Algoritma tidak dikenal: {a}")
                        continue

                    key_val = (request.form.get(f'key_{a}') or '').strip()
                    session[f'profile_key_{a}'] = key_val
                    ciphertext, enc_time = enc_fn(data, key_val)
                    size = len(ciphertext)

                    # stored filename: <timestamp>_<basename>_<ALG>.<ext>
                    stored_name = f"{timestamp}_{base_name}_{a}{ext}"
                    encrypted_path = os.path.join(ENCRYPTED_FOLDER, stored_name)
                    with open(encrypted_path, 'wb') as ef:
                        ef.write(ciphertext)

                    # DB insert
                    cur.execute(
                        """
                        INSERT INTO encrypted_files (owner_id, filename, stored_filename, algorithm, ciphertext, ciphertext_size, enc_time, file_type)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (session['user_id'], filename, stored_name, a, ciphertext, size, enc_time, file_type),
                    )
                    file_id = cur.lastrowid
                    cur.execute(
                        "UPDATE users SET profile_file_id=%s WHERE id=%s",
                        (file_id, session['user_id']),
                    )
                    conn.commit()
                    
                    try:
                        cur.execute(
                            """
                            INSERT INTO logs (user_id, file_id, operation, algorithm, duration)
                            VALUES (%s,%s,%s,%s,%s)
                            """,
                            (session['user_id'], file_id, 'encrypt', a, enc_time)
                        )
                        conn.commit()
                    except Exception as log_error:
                        flash(f"Tidak dapat menyimpan log: {log_error}")
                        pass
                    
                if file_id:
                    flash(f"Berhasil mengenkripsi {len(algos)} varian file.")
                    flash('Gambar profil telah diunggah.')
                else:
                    flash('Tidak ada hasil enkripsi. Periksa pilihan algoritma Anda.')
            except Exception as e:
                flash(f"Gagal mengenkripsi file: {str(e)}")
            finally:
                cur.close(); conn.close()
        else:
            flash('Tidak ada gambar yang dipilih.')
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user, profile_data=profile_data)

# -------------------------
# Upload Report Page 
# -------------------------
@app.route('/upload_report', methods=['GET', 'POST'])
@login_required
def upload_report():
    results = []
    if request.method == 'POST':
        report = request.files.get('report_file')
        algos = request.form.getlist('algorithms')  # values: AES, DES, RC4

        if not report:
            flash('Pilih file terlebih dahulu.')
            return redirect(url_for('upload_report'))
        if not report.filename.lower().endswith(('.xlsx', '.csv', '.txt')):
            flash('Pilih file dengan ekstensi .xlsx, .csv, atau .txt.')
            return redirect(url_for('upload_report'))
        if not algos:
            flash('Pilih minimal satu algoritma.')
            return redirect(url_for('upload_report'))

        missing = [a for a in algos if not (request.form.get(f'key_{a}') or '').strip()]
        if missing:
            flash('Key wajib diisi untuk: ' + ', '.join(missing))
            return redirect(url_for('upload_report'))

        filename = secure_filename(report.filename)
        base_name, ext = os.path.splitext(filename)
        ext_no_dot = ext.lower().lstrip('.')

        if ext_no_dot in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff']:
            file_type = 'image'
        elif ext_no_dot in ['xlsx', 'xls', 'csv']:
            file_type = 'spreadsheet'
        elif ext_no_dot in ['txt', 'dat', 'num']:
            file_type = 'numerical'
        else:
            file_type = 'other'

        data = report.read()
        conn = get_db(); cur = conn.cursor()
        try:
            for a in algos:
                timestamp = int(time.time() * 1000) # milliseconds      
                
                if a == 'AES':
                    enc_fn = aes_encrypt_bytes
                elif a == 'DES':
                    enc_fn = des_encrypt_bytes
                elif a == 'RC4':
                    enc_fn = rc4_encrypt_bytes
                else:
                    flash(f"Algoritma tidak dikenal: {a}")
                    continue

                key_val = (request.form.get(f'key_{a}') or '').strip()
                ciphertext, enc_time = enc_fn(data, key_val)
                size = len(ciphertext)

                stored_name = f"{timestamp}_{base_name}_{a}{ext}"
                encrypted_path = os.path.join(ENCRYPTED_FOLDER, stored_name)
                with open(encrypted_path, 'wb') as ef:
                    ef.write(ciphertext)

                # DB insert
                cur.execute(
                    """
                    INSERT INTO encrypted_files (owner_id, filename, stored_filename, algorithm, ciphertext, ciphertext_size, enc_time, file_type)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (session['user_id'], filename, stored_name, a, ciphertext, size, enc_time, file_type),
                )
                conn.commit()
                file_id = cur.lastrowid
                
                try:
                    cur.execute(
                        """
                        INSERT INTO logs (user_id, file_id, operation, algorithm, duration)
                        VALUES (%s,%s,%s,%s,%s)
                        """,
                        (session['user_id'], file_id, 'encrypt', a, enc_time)
                    )
                    conn.commit()
                except Exception as log_error:
                    flash(f"Tidak dapat menyimpan log: {log_error}")
                    pass  

                results.append({
                    'file': filename,
                    'algorithm': a,
                    'cipher_size': size,
                    'enc_time': f"{enc_time * 1000:.2f} ms",
                    'file_type': file_type,
                    'download_url': url_for('download_file', file_id=file_id) if file_id else None,
                })
            if results:
                flash(f"Berhasil mengenkripsi {len(results)} varian file.")
            else:
                flash('Tidak ada hasil enkripsi. Periksa pilihan algoritma Anda.')
        except Exception as e:
            flash(f"Gagal mengenkripsi file: {str(e)}")
        finally:
            cur.close(); conn.close()
        return render_template('upload_report.html', results=results)
    return render_template('upload_report.html', results=None)

# -------------------------
# Index route
# -------------------------
@app.route('/')
@login_required
def index():
    return render_template('index.html')

# -------------------------
# Files list 
# -------------------------
@app.route('/files')
@login_required
def files_list():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    # File yang dimiliki user (owner)
    cur.execute("""
        SELECT id, filename, stored_filename, algorithm, created_at, 'owned' as source
        FROM encrypted_files 
        WHERE owner_id=%s
    """, (session['user_id'],))
    owned_files = cur.fetchall()
    
    # File yang dibagikan ke user (shared)
    cur.execute("""
        SELECT ef.id, ef.filename, ef.stored_filename, ef.algorithm, ef.created_at, 'shared' as source
        FROM encrypted_files ef 
        JOIN shared_files sf ON ef.id = sf.file_id 
        WHERE sf.shared_user_id=%s
    """, (session['user_id'],))
    shared_files = cur.fetchall()
    
    files = owned_files + shared_files
    files.sort(key=lambda x: x['created_at'], reverse=True)
    cur.execute("SELECT id, username FROM users WHERE id <> %s ORDER BY username ASC", (session['user_id'],))
    users = cur.fetchall()
    cur.close(); conn.close()
    return render_template('files.html', files=files, users=users)

# -------------------------
# Share file
# -------------------------
@app.route('/share/<int:file_id>', methods=['POST'])
@login_required
def share_file(file_id: int):
    shared_user_id = request.form.get('shared_with_user_id', type=int)
    if not shared_user_id:
        flash('Pilih pengguna untuk berbagi file.')
        return redirect(url_for('files_list'))

    if shared_user_id == session['user_id']:
        flash('Tidak bisa berbagi file ke diri sendiri.')
        return redirect(url_for('files_list'))

    conn = get_db(); cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT id, owner_id FROM encrypted_files WHERE id=%s", (file_id,))
        f = cur.fetchone()
        if not f:
            flash('File tidak ditemukan.')
            return redirect(url_for('files_list'))
        if f['owner_id'] != session['user_id']:
            flash('Anda tidak berhak membagikan file ini.')
            return redirect(url_for('files_list'))

        # Cek apakah sudah pernah dibagikan
        cur.execute("SELECT 1 FROM shared_files WHERE file_id=%s AND shared_user_id=%s", (file_id, shared_user_id))
        exists = cur.fetchone() is not None
        if exists:
            flash('File sudah dibagikan ke pengguna tersebut.')
            return redirect(url_for('files_list'))

        cur2 = conn.cursor()
        cur2.execute(
            "INSERT INTO shared_files (owner_id, file_id, shared_user_id) VALUES (%s,%s,%s)",
            (session['user_id'], file_id, shared_user_id)
        )
        conn.commit()
        cur2.close()
        flash('File berhasil dibagikan.')
    except Exception as e:
        flash(f'Gagal membagikan file: {e}')
    finally:
        cur.close(); conn.close()
    return redirect(url_for('files_list'))

@app.route('/download/<int:file_id>', methods=['GET', 'POST'])
@login_required
def download_file(file_id: int):
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM encrypted_files WHERE id=%s", (file_id,))
    f = cur.fetchone()
    if not f:
        cur.close(); conn.close()
        flash('File tidak ditemukan.')
        return redirect(url_for('files_list'))
    
    # Cek authorization
    allowed = (f['owner_id'] == session['user_id'])
    if not allowed:
        cur.execute("SELECT 1 FROM shared_files WHERE file_id=%s AND shared_user_id=%s", (file_id, session['user_id']))
        allowed = cur.fetchone() is not None

    cur.close(); conn.close()
    if not allowed:
        flash('Anda tidak memiliki akses ke file ini.')
        return redirect(url_for('files_list'))

    if request.method == 'POST':
        algorithm = f['algorithm']
        ciphertext = f['ciphertext']
        key = request.form.get('decrypt_key', '').strip()
        
        if not key:
            flash('Key dekripsi wajib diisi.')
            return redirect(url_for('files_list'))

        try:
            if algorithm == 'AES':
                plaintext, dec_time = aes_decrypt_bytes(ciphertext, key)
            elif algorithm == 'DES':
                plaintext, dec_time = des_decrypt_bytes(ciphertext, key)
            elif algorithm == 'RC4':
                plaintext, dec_time = rc4_decrypt_bytes(ciphertext, key)
            else:
                flash('Algoritma tidak dikenal.')
                return redirect(url_for('files_list'))
            
            try:
                conn = get_db(); cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO logs (user_id, file_id, operation, algorithm, duration)
                    VALUES (%s,%s,%s,%s,%s)
                    """,
                    (session['user_id'], file_id, 'decrypt', algorithm, dec_time)
                )
                conn.commit()
                cur.close(); conn.close()
            except Exception as log_error:
                print(f"Warning: Could not save decrypt log: {log_error}")
                pass
            
            filename = f['filename']
            base_name, ext = os.path.splitext(filename)
            timestamp = int(time.time() * 1000)
            decrypted_filename = f"decrypted_{timestamp}_{base_name}{ext}"
            decrypted_path = os.path.join(DECRYPTED_FOLDER, decrypted_filename)
            
            with open(decrypted_path, 'wb') as df:
                df.write(plaintext)
            
            try:
                conn = get_db(); cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO decrypted_files (encrypted_id, user_id, decrypted_filename, dec_time)
                    VALUES (%s,%s,%s,%s)
                    """,
                    (file_id, session['user_id'], decrypted_filename, dec_time)
                )
                conn.commit()
                cur.close(); conn.close()
            except Exception as db_error:
                flash(f"Tidak dapat menyimpan ke decrypted_files: {db_error}")
                pass
            
            flash(f'File berhasil didekripsi: {filename}')
            return send_from_directory(DECRYPTED_FOLDER, decrypted_filename, as_attachment=True, download_name=filename)
            
        except ValueError as ve:
            flash(f'Key salah atau file corrupt: {str(ve)}')
            return redirect(url_for('files_list'))
        except Exception as e:
            flash(f'Gagal mendekripsi file: {str(e)}')
            return redirect(url_for('files_list'))
    
    stored_name = f.get('stored_filename') or f.get('filename')
    return send_from_directory(ENCRYPTED_FOLDER, stored_name, as_attachment=True)

# -------------------------
# Profile Image Preview 
# -------------------------
@app.route('/profile_image_preview')
@login_required
def profile_image_preview():
    conn = get_db(); cur = conn.cursor(dictionary=True)    
    cur.execute("SELECT profile_file_id FROM users WHERE id=%s", (session['user_id'],))
    user = cur.fetchone()
    
    if not user or not user['profile_file_id']:
        cur.close(); conn.close()
        return redirect(url_for('profile'))
    
    # Ambil data file terenkripsi
    cur.execute("SELECT * FROM encrypted_files WHERE id=%s", (user['profile_file_id'],))
    encrypted_file = cur.fetchone()
    cur.close(); conn.close()
    if not encrypted_file:
        return redirect(url_for('profile'))

    algorithm = encrypted_file['algorithm']
    ciphertext = encrypted_file['ciphertext']

    key = session.get(f'profile_key_{algorithm}')
    if not key:
        return redirect(url_for('profile'))
        
    try:
        if algorithm == 'AES':
            plaintext, dec_time = aes_decrypt_bytes(ciphertext, key)
        elif algorithm == 'DES':
            plaintext, dec_time = des_decrypt_bytes(ciphertext, key)
        elif algorithm == 'RC4':
            plaintext, dec_time = rc4_decrypt_bytes(ciphertext, key)
        else:
            return redirect(url_for('profile'))
        
        try:
            conn = get_db(); cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO logs (user_id, file_id, operation, algorithm, duration)
                VALUES (%s,%s,%s,%s,%s)
                """,
                (session['user_id'], user['profile_file_id'], 'decrypt', algorithm, dec_time)
            )
            conn.commit()
            cur.close(); conn.close()
        except Exception as log_error:
            flash(f"Tidak dapat menyimpan log: {log_error}")
            pass  

        filename = encrypted_file['filename']
        ext = os.path.splitext(filename)[1].lower()
        mime_types = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp'
        }
        mime_type = mime_types.get(ext, 'image/jpeg')
        return Response(plaintext, mimetype=mime_type)
    except Exception as e:
        flash(f"Tidak dapat menampilkan gambar profil: {e}")
        return redirect(url_for('profile'))


if __name__ == '__main__':
    app.run(debug=True)
