import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

private_key_b64 = base64.b64encode(private_pem).decode()
public_key_b64 = base64.b64encode(public_pem).decode()

print("Salin 2 baris ini ke file .env:")
print()
print(f"EVOTING_RSA_PRIVATE_KEY_B64={private_key_b64}")
print(f"EVOTING_RSA_PUBLIC_KEY_B64={public_key_b64}")