
from flask import Flask
from flask_bcrypt import Bcrypt
from crypto.crypto_utils import CryptoUtils
app = Flask(__name__)
crypto_utils = CryptoUtils()
crypto_utils.init_app(app)
# Contraseña que quieres usar para 'admin'
admin_password = 'password'

# ¡CRÍTICO! Inicializar una aplicación Flask (aunque sea dummy)
# y luego inicializar Bcrypt con esa aplicación.

# Opcional pero buena práctica: establecer un SECRET_KEY para Flask
enter_password = input ("Enter the password: ")
app.config.from_mapping(
    SECRET_KEY = enter_password
)
# Ahora, 'bcrypt' en tu script se referirá a esta instancia de Flask-Bcrypt


hashed_admin_password = crypto_utils.hash_password(admin_password)

key_salt = crypto_utils.create_salt()

derivation_key = crypto_utils.get_key(admin_password,key_salt)

user_encryption_key = crypto_utils.generate_fernet_key()

encrypted_user_key = crypto_utils.encrypt_derivation(derivation_key, user_encryption_key)

# Convertirlo a formato hexadecimal para SQL X'...'
admin_encryption_salt_hex = key_salt.hex().upper() # ¡CORREGIDO! Usar .hex().upper()

print(f"Admin Hashed Password: {hashed_admin_password}")
print(f"Admin Encryption Salt (HEX): {admin_encryption_salt_hex}")
print(f"Admin Encrypted User Key : {encrypted_user_key}") # ¡CORREGIDO! Imprimir la versión HEX