import qrcode
import pyotp
from qrcode.image.styledpil import StyledPilImage
import os

class QR2FAUtils():
    def __init__(self, qr_path):
        self.qrcode = qrcode.QRCode(
            version = 3,
            error_correction = qrcode.constants.ERROR_CORRECT_H,
            box_size = 10,
            border = 4
        )
        self.qr_path = qr_path

    def generate_uri_qrcode(self, uri_totp, basepath):
        """
        Generates de QR code image and returns and creates the blob of the image to be stored in the DB
        """
        self.qrcode.add_data(uri_totp)
        embedded_image_path = os.path.join(basepath, 'images', 'my_cat.png')
        img = self.qrcode.make_image(image_factory=StyledPilImage, embedded_image_path=embedded_image_path)
        qr_filename = 'my_qr.png'
        self.qr_path = os.path.join(basepath, 'images', qr_filename)
        img.save(self.qr_path)
        return self.qr_path
    
    def generate_uri(self, secret, user):
        """
        Generates the uri using the secret and the user
        """
        uri_totp = pyotp.TOTP(secret).provisioning_uri(name=user, issuer_name="Flasky")
        return uri_totp
    
    def create_secret_for_2fa(self):
        """
        Used for creating the secret that's saved to the DB, pending implementation of encrypting it
        """
        secret_for_2fa = pyotp.random_base32()
        return secret_for_2fa
    
    def validate_token(self, token, secret):
        totp = pyotp.TOTP(secret)
        totp.now()
        valid_token = totp.verify(token)
        return valid_token
        
    def create_blob_qr(self):
        with open(self.qr_path, 'rb') as file:
            qr_blob = file.read()
        return qr_blob
    
    def clean_qr_code(self):
        try:
            os.remove(self.qr_path)
        except Exception as e:
            return f"Error when deleting the QRcode: {e}"