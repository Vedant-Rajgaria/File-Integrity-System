import hashlib
import os
import sqlite3
import subprocess
import base64
import sys
import tkinter as tk
from tkinter import messagebox
import ctypes
from ctypes import wintypes

lookup = os.path.join(os.path.dirname(os.path.abspath(__file__)), "file_tracker.enc")

def get_db() -> sqlite3.Connection:
    """Loads encrypted database from disk directly into RAM, or initializes an empty in-memory DB."""
    conn = sqlite3.connect(":memory:")
    if os.path.exists(lookup):
        with open(lookup, "rb") as f:
            encrypted_data = f.read()
        if encrypted_data:
            conn.deserialize(dpapi_decrypt(encrypted_data))
            return conn

    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS file_manifest (
                file_path TEXT PRIMARY KEY,
                sha256_hash TEXT NOT NULL,
                last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    return conn

def save_db(conn: sqlite3.Connection):

    raw_bytes = conn.serialize()
    encrypted_bytes = dpapi_encrypt(raw_bytes)
    with open(lookup, "wb") as f:
        f.write(encrypted_bytes)

def hashed(file_path):

    hasher = hashlib.sha256()
    with open(file_path, 'rb') as binary_file:
        while chunk := binary_file.read(65536):
            hasher.update(chunk)

    return hasher.hexdigest()

def integrityCheck(file_path):

    conn = get_db()

    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT sha256_hash FROM file_manifest WHERE file_path = ?", (file_path,))
        row = cursor.fetchone()
    if row:
        expectedHash = row[0]
        if hashed(file_path) == expectedHash:
            messagebox.showinfo("File is Secure")
        else:
            messagebox.showerror("File Integrity has compromised!")
    else:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        if messagebox.askyesno("Untracked File", f"'{os.path.basename(file_path)}' is not in the database.\n\nWould you like to register it now?"):
            registerFile(file_path)
        root.destroy()
    conn.close()

def registerFile(file_path):

    if not windows_hello_auth(f"Authorize baseline update for {os.path.basename(file_path)}"):
        print("[Denied] Windows Hello authentication failed or cancelled.")
        return

    conn = get_db()
    with conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO file_manifest (file_path, sha256_hash, last_scanned)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (file_path, hashed(file_path)))
            conn.commit()
    save_db(conn)
    conn.close()

def FilePath(file):
    file_path = file if os.path.isabs(file) else os.path.abspath(file)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file '{file_path}' could not be found.")
    
    return file_path 

def windows_hello_auth(prompt="Authorize Baseline Update") -> bool:
    ps_cmd = f"""
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync('{prompt}')
$getAwaiter = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {{
    $_.Name -eq 'GetAwaiter' -and $_.GetParameters().Length -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
}}
$typedMethod = $getAwaiter.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerificationResult])
$awaiter = $typedMethod.Invoke($null, @($op))
Write-Output $awaiter.GetResult().ToString()
"""
    encoded = base64.b64encode(ps_cmd.encode("utf-16le")).decode("ascii")
    res = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
    )
    return res.stdout.strip() == "Verified"

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

def dpapi_encrypt(data: bytes) -> bytes:
    in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    ctypes.windll.crypt32.CryptProtectData(ctypes.byref(in_blob), "FIM_STORE", None, None, None, 0, ctypes.byref(out_blob))
    buf = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return buf

def dpapi_decrypt(data: bytes) -> bytes:
    in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
    buf = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return buf

if __name__ == "__main__":

    if len(sys.argv) > 2:
        action = sys.argv[1]
        raw_file = sys.argv[2]
    elif len(sys.argv) == 2:
        action = "--check"
        raw_file = sys.argv[1]
    else:
        action = "--check"
        raw_file = input()

    try:
        file_path = FilePath(raw_file)
    except FileNotFoundError as err:
        print(f"[Error] {err}")
        sys.exit(1)

    if action == "--register":
        registerFile(file_path)
    else:
        integrityCheck(file_path)