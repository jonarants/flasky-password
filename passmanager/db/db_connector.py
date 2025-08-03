from secrets.read_secrets import ReadSecrets
import mysql.connector

class DBConfigLoader:
    
    def __init__(self, read_secrets : ReadSecrets):
        if not isinstance(read_secrets, ReadSecrets):
            raise TypeError("read_secrets must be an instance of ReadSecrets.")
        self.read_secrets = read_secrets
    
    def create_connection_cursor(self) -> tuple:
        connection = None
        cursor = None
        config = {
            'user': self.read_secrets.get_secret('mysql_user_secret'),
            'password': self.read_secrets.get_secret('mysql_password_secret'),
            'host': self.read_secrets.get_secret('mysql_host_secret'),
            'port': self.read_secrets.get_secret('mysql_port_secret'),
            'database': self.read_secrets.get_secret('mysql_database_secret')
        }
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor(dictionary=True)
        return connection, cursor