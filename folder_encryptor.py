import os
import secrets
import tempfile
import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

FOLDER_PATH = r"..."

MAGIC = b"XENC1"
SALT_SIZE = 16 
NONCE_SIZE = 12
KDF_ITERATIONS = 600_000
KEY_SIZE = 32


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def is_encrypted(filepath: str) -> bool:
    try:
        with open(filepath, "rb") as f:
            header = f.read(len(MAGIC))
        return header == MAGIC
    except OSError:
        return False


def _atomic_replace(filepath: str, data: bytes) -> None:
    directory = os.path.dirname(os.path.abspath(filepath)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp_path, filepath)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def encrypt_file(filepath: str, password: str) -> None:
    if is_encrypted(filepath):
        raise ValueError("already encrypted")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)

    with open(filepath, "rb") as f:
        plaintext = f.read()

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    _atomic_replace(filepath, MAGIC + salt + nonce + ciphertext)


def decrypt_file(filepath: str, password: str) -> None:
    if not is_encrypted(filepath):
        raise ValueError("not encrypted")

    with open(filepath, "rb") as f:
        raw = f.read()

    body = raw[len(MAGIC):]
    salt = body[:SALT_SIZE]
    nonce = body[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = body[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    _atomic_replace(filepath, plaintext)


def _iter_files(folder_path: str):
    for dirpath, _dirnames, filenames in os.walk(folder_path):
        for name in filenames:
            yield os.path.join(dirpath, name)


def process_folder(folder_path: str, password: str, mode: str):
    """mode is 'encrypt' or 'decrypt'. Returns (done, skipped, failed)."""
    action = encrypt_file if mode == "encrypt" else decrypt_file
    already_done_check = is_encrypted if mode == "decrypt" else (lambda p: not is_encrypted(p))

    done, skipped, failed = 0, 0, []
    for path in _iter_files(folder_path):
        try:
            if mode == "encrypt" and is_encrypted(path):
                skipped += 1
                continue
            if mode == "decrypt" and not is_encrypted(path):
                skipped += 1
                continue

            action(path, password)
            done += 1
        except Exception as e:
            failed.append((path, str(e)))

    return done, skipped, failed


def main():
    if not os.path.isdir(FOLDER_PATH):
        print(f"Folder not found: {FOLDER_PATH}")
        print("Edit the FOLDER_PATH variable at the top of this script and try again.")
        return

    print(f"Target folder: {FOLDER_PATH}")
    print()
    print("What do you want to do?")
    print("  1 - Encrypt all files in this folder")
    print("  2 - Decrypt all files in this folder")
    choice = input("Enter 1 or 2: ").strip()

    if choice not in ("1", "2"):
        print("Invalid choice. Exiting.")
        return

    mode = "encrypt" if choice == "1" else "decrypt"

    if mode == "encrypt":
        print()
        print(f"  This will encrypt EVERY file inside:\n    {FOLDER_PATH}")
        print("    (including all subfolders)")
        confirm = input("Type 'yes' to continue: ").strip().lower()
        if confirm != "yes":
            print("Cancelled.")
            return

        password = getpass.getpass("Choose a password for encryption: ")
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Passwords do not match. Exiting.")
            return
    else:
        password = getpass.getpass("Enter password to decrypt: ")

    print()
    print("Working...")
    done, skipped, failed = process_folder(FOLDER_PATH, password, mode)

    print()
    print(f" {done} file(s) {mode}ed")
    if skipped:
        print(f"  {skipped} file(s) skipped (already in the right state)")
    if failed:
        print(f" {len(failed)} file(s) failed:")
        for path, err in failed[:10]:
            print(f"   - {path}: {err}")
        if len(failed) > 10:
            print(f"   ...and {len(failed) - 10} more")


if __name__ == "__main__":
    main()
