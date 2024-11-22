import secrets

def generate_keys():
    # Generate a 32-byte random key for AES-256 encryption and convert to hexadecimal
    encryption_key = secrets.token_bytes(32).hex()
    
    # Generate a 32-byte (64-character) hexadecimal key for Flask's SECRET_KEY
    secret_key = secrets.token_hex(32)
    
    return secret_key, encryption_key

# Generate the keys
secret_key, encryption_key = generate_keys()

# Output the keys
print("SECRET_KEY (Hex):")
print(secret_key)
print("\nENCRYPTION_KEY (Hex):")
print(encryption_key)
