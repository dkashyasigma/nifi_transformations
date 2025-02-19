import json
import sys
import os
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

PAD_CHAR = "_"  # Padding character for fixed-length fields

def encrypt_data(data, key, original_length):
    # Ensure data is a string and encode as UTF-8
    data = data.encode("utf-8")  
    
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # IV should be exactly 16 bytes
    encrypted_bytes = cipher.encrypt(pad(data, AES.block_size))
    
    # Encode IV + Encrypted Data in Base64
    encoded = base64.b64encode(iv + encrypted_bytes).decode("utf-8")

    # Ensure encrypted output matches field length using padding
    if len(encoded) < original_length:
        encoded = encoded.ljust(original_length, PAD_CHAR)

    return encoded  # Ensure full IV is stored

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
                if isinstance(record[field], int):
                    record[field] = str(record[field])
                original_length = len(record[field])
                record[field] = encrypt_data(record[field], key, original_length)

    print(json.dumps(records, indent=2, ensure_ascii=False))  # Ensure correct character encoding

if __name__ == "__main__":
    main()
