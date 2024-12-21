from cryptography.fernet import Fernet

# Generate a Fernet key
key = Fernet.generate_key()

# Print the key
print("Generated Fernet key:", key.decode())
