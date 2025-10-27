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

## Dokumentasi

### 1. Login and Register User
Users can log in using an existing account or create a new one to access the system. The registration form requires basic information such as username and password, which are securely stored using hashing
<img width="1856" height="918" alt="image" src="https://github.com/user-attachments/assets/a50e1fa3-1a97-4140-9099-f6aaf17377e3" />
<img width="1845" height="926" alt="image" src="https://github.com/user-attachments/assets/cd7ac3ea-3a0b-4dfa-baa2-2095501da05f" />

### 2. Home Page
The home page displays an overview of the system, providing a brief explanation of the implemented Secure Financial Report System and its available features
<img width="1850" height="929" alt="image" src="https://github.com/user-attachments/assets/11aa6018-fc0c-4d2f-9dfc-2c830877f508" />

### 3. Upload Report Page
Users can upload files in the following formats: .xlsx, .csv, or .txt.
Before saving the file, users must:
- Select the desired encryption algorithm (AES, DES, or RC4)
- Enter the appropriate encryption key for the selected algorithm

wrong key
<img width="1857" height="923" alt="image" src="https://github.com/user-attachments/assets/cad19ead-1802-4db2-a142-40d245397894" />
<img width="1847" height="693" alt="image" src="https://github.com/user-attachments/assets/f2b58cc2-f9fb-4ba0-8736-e0b4aab592cb" />

correct key
<img width="1857" height="716" alt="image" src="https://github.com/user-attachments/assets/546e2e86-f278-4a06-9346-85d09fb73275" />
<img width="1827" height="923" alt="image" src="https://github.com/user-attachments/assets/156a5b95-6ac1-4841-839f-c9d5983dbb07" />
After encryption, users can view a list of all successfully encrypted files

### 5. Profile Page
This page displays the user’s profile information, including their username and profile picture. Users can upload or change their profile image or logo (JPG, PNG), which will also be encrypted for security. Additionally, users can choose their preferred encryption algorithm and set their personal encryption key.
<img width="1854" height="692" alt="image" src="https://github.com/user-attachments/assets/98dc9441-c1f6-42f2-9fc0-6c2a21b3fc30" />
<img width="1852" height="711" alt="image" src="https://github.com/user-attachments/assets/62b30530-510d-4414-b497-5d92484b2c07" />

### 6. Decrypt and Share Page
<img width="1855" height="900" alt="image" src="https://github.com/user-attachments/assets/d2aba8bc-9746-4851-9dee-c4e7d976f5d6" />
This page allows users to:

- **Decrypt** encrypted files by entering the correct key for the corresponding algorithm. Once decrypted, the file will be automatically downloaded
  <img width="1854" height="844" alt="image" src="https://github.com/user-attachments/assets/24081e08-185f-4164-9e54-1eb3f09fd110" />

- **Share** encrypted files with other registered users within the system for secure collaboration
  <img width="1849" height="858" alt="image" src="https://github.com/user-attachments/assets/6d5d86e7-3582-40e1-b8b1-49f1aa5f1da0" />
  <img width="1852" height="456" alt="image" src="https://github.com/user-attachments/assets/a9c1fc5e-aef1-4f48-98eb-4ba2148b7d3b" />

### 7. Performance Page





