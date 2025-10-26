# Information Security 2025

**Team Name:** fanspakbas

| No | Name                        |    NRP     |
|----|-----------------------------|------------|
| 1  | Haliza Nur Kamila Apalwan   | 5025231038 |
| 2  | Alma Khusnia                | 5025231063 |
| 3  | Andi Nur Nabila S           | 5025231104 |
| 4  | Sharfina Ardhiyanti Anam    | 5025231111 |

## Overview

A web application built with **Flask** and **MySQL** that allows users to register, upload, and share encrypted files securely.  
Encryption algorithms supported include **AES**, **DES**, and **RC4**.

---

## Features

- User registration and login (with password hashing)
- File upload, encryption, and decryption
- File sharing between registered users
- Encrypted file storage on the server
- Encrypted metadata stored in the database

---

## Requirements

- Python 3.8+
- MySQL Server
- Flask and related dependencies (see `requirements.txt`)

---

## Project Structures

```
Information Security 2025/
│
├── app.py
├── db.py
├── requirements.txt
│
├── crypto_algorithms/
│   ├── aes_encryptor.py
│   ├── des_encryptor.py
│   └── rc4_encryptor.py
│
├── static/
│   ├── css/
│   |    └── styles.css
│   ├── images/
│   |    └── background.jpg
│   ├── js/
│   |    └── script.js
│   └── templates/
|
├── templates/
│   ├── base.html
│   ├── files.html
│   ├── index.html
│   ├── login.html
│   ├── performance.html
│   ├── profile.html
│   ├── register.html
│   └── upload_report.html
│
├── encrypted_files/
│   └── (encrypted output files)
│
└── decrypted_files/
    └── (decrypted output files)

```


## Setup Instructions

### 1. Clone Repository

```bash
git clone https://github.com/username/repo-name.git
cd repo-name
```

### 2. Create Virtual Environment

Option A - using Anaconda
```
conda create --name flask-encrypt python=3.10
conda activate flask-encrypt
pip install -r requirements.txt
```

Option B - using `venv`
```
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux
pip install -r requirements.txt
```

### 3. Configure Database

Make a new database
```
CREATE DATABASE fanspakbas;
```

Change the configuration database in `app.py`

```
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',       
    'database': 'fanspakbas'
}
```

### 4. Run Apps
```
python app.py
```





