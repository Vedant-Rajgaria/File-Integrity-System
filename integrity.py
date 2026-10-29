import hashlib
import os
import sqlite3
import subprocess
import base64
import sys

lookup = os.path.join(os.environ.get("LOCALAPPDATA", "."), "file_tracker.db")

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

def integrityCheck(file_path):

    with sqlite3.connect(lookup) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT sha256_hash FROM file_manifest WHERE file_path = ?", (file_path))
        row = cursor.fetchone()
    expectedHash = row[0]
    print("File Secure") if hashed(file_path) == expectedHash else print ("File Integrity is compromised")

def registerFile(file_path):

    if not windows_hello_auth(f"Authorize baseline update for {os.path.basename(file_path)}"):
        print("[Denied] Windows Hello authentication failed or cancelled.")
        return

    with sqlite3.connect(lookup) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO file_manifest (file_path, sha256_hash, last_scanned)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (file_path, hashed(file_path)))
            conn.commit()

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

if __name__ == "__main__":

    if len(sys.argv) > 2:
        action = sys.argv[1]
        raw_file = sys.argv[2]
    elif len(sys.argv) == 2:
        action = "--check"
        raw_file = sys.argv[1]

    try:
        file_path = FilePath(raw_file)
    except FileNotFoundError as err:
        print(f"[Error] {err}")
        sys.exit(1)

    if action == "--register":
        registerFile(file_path)
    else:
        integrityCheck(file_path)