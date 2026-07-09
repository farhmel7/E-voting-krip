import os
from cryptography.fernet import Fernet


print("Copy hasil di bawah ini ke file .env")
print()
print("FLASK_SECRET_KEY=" + os.urandom(32).hex())
print("EVOTING_ENCRYPTION_KEY=" + Fernet.generate_key().decode())
print("EVOTING_HMAC_KEY=" + os.urandom(32).hex())