import os
import hashlib
import requests

from flask import Flask, request, jsonify, send_file, send_from_directory

from flask import Flask, request, jsonify, send_file
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

import io

app = Flask(__name__)

# ---------- Constants ----------
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERATIONS = 100_000
CHUNK_SIZE = 64 * 1024

# Vercel Blob environment variable
BLOB_TOKEN = os.environ.get("BLOB_READ_WRITE_TOKEN")
if not BLOB_TOKEN:
    raise RuntimeError("BLOB_READ_WRITE_TOKEN not set in environment")

BLOB_API_URL = "https://blob.vercel-storage.com"

def derive_key(password: bytes, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS,
                  hmac_hash_module='SHA512')

def encrypt_bytes(data: bytes, password: str) -> bytes:
    """Encrypt bytes with password, returns salt+nonce+ciphertext+tag."""
    pwd = password.encode('utf-8')
    salt = get_random_bytes(SALT_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)
    key = derive_key(pwd, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext = cipher.encrypt(data)
    tag = cipher.digest()
    return salt + nonce + ciphertext + tag

def decrypt_bytes(encrypted: bytes, password: str) -> bytes:
    """Decrypt bytes, raises ValueError if password wrong or data corrupted."""
    pwd = password.encode('utf-8')
    salt = encrypted[:SALT_SIZE]
    nonce = encrypted[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    tag_start = len(encrypted) - TAG_SIZE
    ciphertext = encrypted[SALT_SIZE+NONCE_SIZE:tag_start]
    tag = encrypted[tag_start:]
    key = derive_key(pwd, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt(ciphertext)
    cipher.verify(tag)  # may raise ValueError
    return plain

def get_blob_key(code: str) -> str:
    """Deterministic blob name from code."""
    h = hashlib.sha256(code.encode('utf-8')).hexdigest()
    return f"files/{h}.enc"

def upload_blob(blob_name: str, data: bytes) -> None:
    """Upload to Vercel Blob using REST API."""
    url = f"{BLOB_API_URL}/upload?path={blob_name}"
    headers = {
        "Authorization": f"Bearer {BLOB_TOKEN}",
        "Content-Type": "application/octet-stream"
    }
    resp = requests.put(url, headers=headers, data=data)
    if resp.status_code != 200:
        raise Exception(f"Upload failed: {resp.text}")

def download_blob(blob_name: str) -> bytes:
    """Download from Vercel Blob."""
    url = f"{BLOB_API_URL}/download?path={blob_name}"
    headers = {"Authorization": f"Bearer {BLOB_TOKEN}"}
    resp = requests.get(url, headers=headers)
    if resp.status_code == 404:
        return None  # not found
    if resp.status_code != 200:
        raise Exception(f"Download failed: {resp.text}")
    return resp.content

# ---------- API Routes ----------
@app.route('/upload', methods=['POST'])
def upload():
    code = request.form.get('code')
    file = request.files.get('file')
    if not code or not file:
        return jsonify({"error": "Missing code or file"}), 400

    # Encrypt the file bytes
    file_bytes = file.read()
    encrypted_data = encrypt_bytes(file_bytes, code)

    # Store in Blob
    blob_name = get_blob_key(code)
    upload_blob(blob_name, encrypted_data)

    return jsonify({"message": "File uploaded successfully"}), 200

@app.route('/download', methods=['GET'])
def download():
    code = request.args.get('code')
    if not code:
        return jsonify({"error": "Missing code"}), 400

    blob_name = get_blob_key(code)
    encrypted_data = download_blob(blob_name)
    if encrypted_data is None:
        return jsonify({"error": "No file found for this code"}), 404

    try:
        decrypted_data = decrypt_bytes(encrypted_data, code)
    except ValueError:
        return jsonify({"error": "Invalid code or corrupted data"}), 403

    # Return the decrypted file as a download
    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name="decrypted_file"
    )

# For local development
if __name__ == '__main__':
    app.run(debug=True)
