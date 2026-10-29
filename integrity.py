import hashlib
import os
import sqlite3

lookup = "file_tracker.db"

with sqlite3.connect(lookup) as conn:
    cursor = conn.cursor()
    cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_manifest (
                    file_path TEXT PRIMARY KEY,
                    sha256_hash TEXT NOT NULL,
                    last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
    conn.commit()

def hashed(file_path):

    hasher = hashlib.sha256()
    with open(file_path, 'rb') as binary_file:
        while chunk := binary_file.read(65536):
            hasher.update(chunk)

    return hasher.hexdigest()

def integrityCheck(file_path,expectedHash ):
    print("File Secure") if hashed(file_path) == expectedHash else print ("File Integrity is compromised")

def registerFile(file_path):
    with sqlite3.connect(lookup) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO file_manifest (file_path, sha256_hash, last_scanned)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (file_path, hashed(file_path)))
            conn.commit()

def FilePath(file):
    file_path = file if os.path.isabs(file) else file_path = os.path.abspath(file) #alternative: path().resolve()
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file '{file_path}' could not be found.")
    
    return file_path 
