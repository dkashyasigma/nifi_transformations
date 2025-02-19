import json
import sys
import os
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

PAD_CHAR = "_"  # Same padding character used in encryption

def decrypt_data(encrypted_data, key):
    try:
        # Remove padding
        encrypted_data = encrypted_data.rstrip(PAD_CHAR)

        # Ensure valid Base64 format
        missing_padding = len(encrypted_data) % 4
        if missing_padding:
            encrypted_data += "=" * (4 - missing_padding)

        # Decode Base64
        encrypted_bytes = base64.b64decode(encrypted_data)

        # Extract IV and Encrypted Content
        iv, encrypted_bytes = encrypted_bytes[:AES.block_size], encrypted_bytes[AES.block_size:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)

        return decrypted_bytes.decode("utf-8")  # Decode as UTF-8 to handle special characters

    except Exception as e:
        return f"DECRYPTION_ERROR: {str(e)}"

def main():
    input_json = sys.stdin.read().strip()

    try:
        records = json.loads(input_json)  # Expecting a list of dictionaries
    except json.JSONDecodeError:
        print("Invalid JSON received", file=sys.stderr)
        sys.exit(1)

    if not isinstance(records, list):
        print("Invalid JSON format: Expected a list of records", file=sys.stderr)
        sys.exit(1)

    pii_fields = os.environ.get("pii_fields", "").split(";")
    key = b"32_byte_encryption_key__"  # Ensure 32 bytes for AES-256

    for record in records:
        for field in pii_fields:
            if field in record and record[field]:
                record[field] = decrypt_data(record[field], key)

    print(json.dumps(records, indent=2, ensure_ascii=False))  # Ensure correct character encoding

if __name__ == "__main__":
    main()
