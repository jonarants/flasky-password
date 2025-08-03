import mysql.connector

class DisconnectDB:
        
    def close_connection_cursor(self,connection, cursor):
        if cursor:
            try:
                cursor.close()
            except Exception as e:
                print (f"Error closing cursor {e}")
        if connection:
            try:
                connection.close()
            except Exception as e:
                print(f"Error closing the connection")
