from cryptography.fernet import Fernet

# Replace this key with a securely stored key (store in environment variables in production)
SECRET_KEY = b'APN77KA6tdiYMx5Xwb4V-PMfSue9z8C9QK6bbMA-pBo='  # Use Fernet.generate_key() to generate a new key
cipher = Fernet(SECRET_KEY)

def encrypt_message(message):
    return cipher.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    return cipher.decrypt(encrypted_message.encode()).decode()
