import mysql.connector

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',       
    'database': 'fanspakbas'
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)