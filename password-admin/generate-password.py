import bcrypt
import os
from flask_bcrypt import Bcrypt
from flask import Flask, render_template, request

# Contraseña que quieres usar para 'admin'
admin_password = 'password'

# ¡CRÍTICO! Inicializar una aplicación Flask (aunque sea dummy)
# y luego inicializar Bcrypt con esa aplicación.
app = Flask(__name__)
# Opcional pero buena práctica: establecer un SECRET_KEY para Flask
app.config['SECRET_KEY'] = 'una_clave_secreta_para_este_script_temporal'
# Ahora, 'bcrypt' en tu script se referirá a esta instancia de Flask-Bcrypt
bcrypt = Bcrypt(app) # <--- Esta línea es la que faltaba para inicializar bcrypt

# Generar el hash de la contraseña
# Ahora, 'bcrypt' es la instancia de Bcrypt de Flask-Bcrypt, y tiene generate_password_hash
hashed_admin_password = bcrypt.generate_password_hash(admin_password, 12).decode('utf-8')

# Generar un salt de cifrado aleatorio (16 bytes)
admin_encryption_salt_bytes = os.urandom(16)
# Convertirlo a formato hexadecimal para SQL X'...'
admin_encryption_salt_hex = admin_encryption_salt_bytes.hex().upper() # ¡CORREGIDO! Usar .hex().upper()

print(f"Admin Hashed Password: {hashed_admin_password}")
print(f"Admin Encryption Salt (HEX): {admin_encryption_salt_hex}") # ¡CORREGIDO! Imprimir la versión HEX