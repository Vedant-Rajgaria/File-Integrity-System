# File Modification Detector

A local File Integrity Monitoring (FIM) utility for Windows. Tracks filesystem integrity using SHA-256 checksums, enforces baseline authorization via Windows Hello biometrics/PIN, and protects the baseline database using Windows DPAPI encryption at rest with in-memory execution.

---

## Technical Architecture

* **Integrity Engine:** Computes 64 KB chunked SHA-256 digests over target files to detect unauthorized modifications.
* **Storage Encryption (DPAPI):** The database (`file_tracker.enc`) is encrypted at rest using Windows Data Protection API (`CryptProtectData`/`CryptUnprotectData`). The container cannot be read by external processes or SQLite tools without execution under the authenticated Windows user account.
* **In-Memory SQLite Lifecycle:** The database is loaded and modified strictly in volatile memory (`sqlite3.connect(":memory:")`) using `deserialize()` and `serialize()`. Plaintext database structures are never written to physical disk.
* **Authorization Gate:** Baseline registrations and modifications require verification via `Windows.Security.Credentials.UI.UserConsentVerifier` (Windows Hello). This prevents unauthorized re-baselining following local file tampering.
* **Shell Integration:** Hooks into the Windows Explorer context menu via `HKCU\Software\Classes\*\shell` to operate on arbitrary file paths.

---

## Requirements

* **Operating System:** Windows 10 or Windows 11 (64-bit)
* **Authentication:** Active Windows Hello provider (PIN, Fingerprint, or Facial Recognition)
* **Runtime:** Python 3.10+ (standard library only; no external dependencies)

---

## File Structure

```text
File Modification Detector/
│
├── integrity.py         # Application entry point, cryptography, DB, and UI handlers
├── file_tracker.enc     # DPAPI-encrypted baseline container (auto-generated)
├── register_menu.reg    # Windows Registry context menu definition
└── README.md            # Technical documentation
```

---

## Command-Line Interface (CLI)

Syntax:
```powershell
python integrity.py [--check | --register] "<file_path>"
```

### Options

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--check` | Yes | Verifies the file's current SHA-256 hash against the baseline in `file_tracker.enc`. Prompts to register if untracked. |
| `--register` | No | Computes file hash and invokes Windows Hello. On successful verification, updates the record in `file_tracker.enc`. |

### Examples

```powershell
# Verify file integrity
python integrity.py --check "C:\path\to\target.bin"

# Register or update baseline (triggers Windows Hello)
python integrity.py --register "C:\path\to\target.bin"
```

---

## Context Menu Integration

The script can be executed directly from File Explorer on any file by registering two verbs under the current user's shell classes.

### Registry Configuration (`register_menu.reg`)

```reg
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Classes\*\shell\FileIntegrity]
"MUIVerb"="File Integrity"
"SubCommands"=""

[HKEY_CURRENT_USER\Software\Classes\*\shell\FileIntegrity\shell\1_Check]
@="Check for Tampering"

[HKEY_CURRENT_USER\Software\Classes\*\shell\FileIntegrity\shell\1_Check\command]
@="\"C:\\Users\\Vedant\\AppData\\Local\\Programs\\Python\\Python314\\pythonw.exe\" \"C:\\Users\\Vedant\\Desktop\\Projects\\File Modification Detector\\integrity.py\" --check \"%1\""

[HKEY_CURRENT_USER\Software\Classes\*\shell\FileIntegrity\shell\2_Register]
@="Update Baseline (Requires Hello)"

[HKEY_CURRENT_USER\Software\Classes\*\shell\FileIntegrity\shell\2_Register\command]
@="\"C:\\Users\\Vedant\\AppData\\Local\\Programs\\Python\\Python314\\pythonw.exe\" \"C:\\Users\\Vedant\\Desktop\\Projects\\File Modification Detector\\integrity.py\" --register \"%1\""
```

### Installation

1. Import `register_menu.reg` into the Windows Registry:
   ```powershell
   reg import register_menu.reg
   ```
2. The commands are available immediately under the right-click menu of any file (on Windows 11, under **Show more options** / `Shift` + `F10`).

### Uninstallation

To remove the context menu entries:
```powershell
reg delete "HKCU\Software\Classes\*\shell\FileIntegrity" /f
```

---

## Execution Workflows

### 1. Integrity Verification Flow (`--check`)
1. Path argument is resolved to an absolute path (`os.path.abspath`).
2. `file_tracker.enc` is read from disk and decrypted into RAM via DPAPI.
3. An in-memory SQLite database is initialized with `conn.deserialize()`.
4. Query executes for `file_path`:
   * **Match:** Current SHA-256 hash matches recorded baseline. Dialog returns `File Secure`.
   * **Mismatch:** Current hash differs from baseline. Dialog returns `Tampering Detected!`.
   * **Untracked:** No baseline found. Prompts user to register. If accepted, routes to the registration flow.
5. In-memory connection is closed and memory is deallocated.

### 2. Baseline Registration Flow (`--register`)
1. Invokes PowerShell to execute `[Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync()`.
2. Windows displays the native security challenge (biometrics or device PIN).
3. If verification status is `Verified`:
   * Hashing engine calculates the file's current SHA-256 digest.
   * `file_manifest` table is updated in memory (`INSERT OR REPLACE`).
   * Database is serialized via `conn.serialize()`.
   * Raw bytes are encrypted via `CryptProtectData` and written to `file_tracker.enc`.
4. If verification fails or is cancelled, execution halts with no disk write.

---

## Database Schema & Inspection

### Schema (`file_manifest`)

```sql
CREATE TABLE file_manifest (
    file_path TEXT PRIMARY KEY,
    sha256_hash TEXT NOT NULL,
    last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Querying Decrypted Database (Debugging)

Because `file_tracker.enc` is encrypted at rest, inspect it using the in-memory loader:

```powershell
python -c "import integrity; conn = integrity.get_db(); print(conn.execute('SELECT * FROM file_manifest').fetchall()); conn.close()"
```
