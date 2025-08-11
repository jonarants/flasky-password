from secrets.read_secrets import ReadSecrets
import mysql.connector

class DBUtils:

    def __init__(self, read_secrets):
        if not isinstance(read_secrets, ReadSecrets):
            raise TypeError("read secrets must be an instandes of ReadSecrets.")
        self.read_secrets = read_secrets
        
    def connect(self):
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
        cursor = connection.cursor(dictionary=True) #False positive
        return connection, cursor
    
    def disconnect(self, connection, cursor):
        if cursor:
            try:
                cursor.close()
            except Exception as e:
                print (f"Error closing cursor {e}")

        if connection:
            try:
                connection.close()
            except Exception as e:
                print(f"Error closing the connection {e}")