import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from flask_bcrypt import Bcrypt
class CryptoUtils():
    def __init__(self, app=None):
        self.bcrypt = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.bcrypt = Bcrypt(app)

    def create_salt(self):
        salt = os.urandom(16)
        return salt
    
    def encrypt_password(self, key, password):
        fernet = Fernet(key)
        return fernet.encrypt(password.encode())
    
    def decrypt_password(self, key, token):
        fernet = Fernet(key)
        return fernet.decrypt(token).decode()
    
    def hash_password(self, password):
        return self.bcrypt.generate_password_hash(password, 12).decode('utf-8')
    
    def generate_fernet_key(self):
        return Fernet.generate_key()
    
    def encrypt_derivation(self,derivation_key, user_encryption_key):
        fernet = Fernet(derivation_key)
        return fernet.encrypt(user_encryption_key)
    
    def decrypt_derivation(self,derivation_key, user_encryption_key):
        fernet = Fernet(derivation_key)
        return fernet.decrypt(user_encryption_key)

    def get_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000, # Ideal para una clave más compleja de encriptacion
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    
    def validate_password(self, dbpassword, inputpassword):
        return self.bcrypt.check_password_hash(dbpassword, inputpassword)