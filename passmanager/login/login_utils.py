
class LoginUtils:

    def __init__(self):
        self.session={}

    def user_auth_role(self, user_record):
        if user_record['admin'] == 1:
            return True
        else:
            return False

