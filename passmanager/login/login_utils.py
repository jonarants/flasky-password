from db.db_utils import DBUtils
from secrets.read_secrets import ReadSecrets
import mysql.connector
class LoginUtils:

    def __init__(self, read_secrets):
        if not isinstance(read_secrets, ReadSecrets):
            raise TypeError("read secrets must be an instance of ReadSecrets.")
        self.read_secrets = read_secrets

    def user_auth_role(self, user_record, password):
        if user_record['admin'] == 1:
            self.session['admin'] = True
        else:
            self.session['admin'] = False

        session = self.session['admin']




        return session
