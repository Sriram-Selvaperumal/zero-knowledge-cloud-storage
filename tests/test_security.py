from app.utils.security import (
    hash_password,
    verify_password
)

password = "hello123"

hashed = hash_password(password)

print("Hash:", hashed)

print(
    "Verification:",
    verify_password(
        password,
        hashed
    )
)