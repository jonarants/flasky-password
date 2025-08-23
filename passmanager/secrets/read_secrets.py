import os
class ReadSecrets:

     def __init__(self, secrets_path='/run/secrets'):
          self.secrets_path = secrets_path
          if not os.path.isdir(self.secrets_path):
               print("The secrets are non-existant in the docker structure, make sure you're running through docker")

     def get_secret(self, secret_name):
          secret_file_path = os.path.join(self.secrets_path,secret_name)
          try:
               with open(secret_file_path, 'r') as f:
                    return f.read().strip()
          except FileNotFoundError:
               raise FileNotFoundError(f"Secret '{secret_name}' no encontrado en '{self.secrets_path}'.")
          except IOError as e:
               raise IOError (f"Error when reading the secret file '{secret_name}':{e}")
               