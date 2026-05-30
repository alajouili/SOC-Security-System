#!/usr/bin/env python3
"""Generate RSA 2048 key pair for JWT signing."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pathlib import Path

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Serialize private key to PEM
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Get public key and serialize to PEM
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Write files
keys_dir = Path(__file__).parent / "keys"
keys_dir.mkdir(exist_ok=True)

with open(keys_dir / 'private.pem', 'wb') as f:
    f.write(private_pem)

with open(keys_dir / 'public.pem', 'wb') as f:
    f.write(public_pem)

print('RSA keys generated successfully at:')
print(f'  {keys_dir / "private.pem"}')
print(f'  {keys_dir / "public.pem"}')
