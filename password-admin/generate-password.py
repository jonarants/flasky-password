import bcrypt
import os

# Contraseña que quieres usar para 'admin'
admin_password = 'password'

# Generar el hash de la contraseña
hashed_admin_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')

# Generar un salt de cifrado aleatorio (16 bytes)
admin_encryption_salt_bytes = os.urandom(16)
# Convertirlo a formato hexadecimal para SQL X'...'
admin_encryption_salt_hex = admin_encryption_salt_bytes.hex().upper()

print(f"Admin Hashed Password: {hashed_admin_password}")
print(f"Admin Encryption Salt (HEX): {admin_encryption_salt_hex}")