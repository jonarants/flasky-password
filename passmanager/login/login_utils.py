
class LoginUtils:

    def __init__(self):
        self.session={}

    def user_auth_role(self, user_record):
        if user_record['admin'] == 1:
            self.session['admin'] = True
        else:
            self.session['admin'] = False

        session = self.session['admin']

        return session
