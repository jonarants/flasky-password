from flask import Flask, render_template, request
from flask_bcrypt import Bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import mysql.connector
import base64
import os
app = Flask(__name__)
bcrypt = Bcrypt (app)


def encrypt_password(key, password):
    fernet = Fernet(key)
    return fernet.encrypt(password.encode())

def decrypt_password(key, token):
    fernet = Fernet(key)
    return fernet.decrypt(token).decode()



app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
def get_db_config():
    SECRETS_PATH =  '/run/secrets'

    def read_secret(secret_name):
        secret_file_path = os.path.join(SECRETS_PATH, secret_name)
        with open(secret_file_path, 'r') as f:
            return f.read().strip()
        
    return {
        'user': read_secret('mysql_user_secret'),
        'password': read_secret('mysql_password_secret'),
        'host': read_secret('mysql_host_secret'),
        'port': read_secret('mysql_port_secret'),
        'database': read_secret('mysql_database_secret')
    }

def hash_password(password):
    return bcrypt.generate_password_hash(password, 12).decode('utf-8')

def load_or_create_salt(call_type, user):
    config = get_db_config()
    connection = mysql.connector.connect(**config)
    cursor = connection.cursor()
    try:
      if call_type == "w":
          salt = os.urandom(16)
          salt_result = salt
      elif call_type == "r": # LA R O W yo las defino, así que no puede haber error de usuario
          cursor.execute('SELECT encryption_salt FROM users WHERE user = %s',(user,))
          salt_result = cursor.fetchone()
          salt_result = salt_result[0]
    except Exception as e:
      print(f"UNEXPECTED ERROR in load_or_create_salt for user_id {user}: {e}")
    finally:
      cursor.close()
      connection.close()    
    return salt_result

def get_key (password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register_user', methods=['POST'])
def register_user():
    user = request.form['user']
    password = request.form['password']
    two_factor_secret = "placeholder data"#request.form['two_factor_secret']
    two_factor_enabled = request.form.get('two_factor_enabled')
    two_factor_enabled = (two_factor_enabled == "Enabled")

    hashed_password = hash_password(password)
    salt = load_or_create_salt("w",user)
    
    #is_valid = bcrypt.check_password_hash(hashed_password, password)
    try: 
        config = get_db_config()
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        cursor.execute('INSERT INTO users (user,password,two_factor_secret,two_factor_enabled,encryption_salt) VALUES (%s,%s,%s,%s,%s)',(user,hashed_password,two_factor_secret,two_factor_enabled,salt))
        connection.commit()
        cursor.close()
        mensaje = f"The {user} was created correctly"
        return render_template ('result_data.html' ,mensaje=mensaje)
    except Exception as e:
        mensaje = f"Error al insertar a la base de datos:" + str(e)
        return render_template('result_data_error.html', mensaje=mensaje)



@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/auth_validation', methods=['POST'])
def auth_validation():
    user = request.form['user']
    password = request.form['password']
    #salt = load_or_create_salt("r",user)
     
    #key = get_key (password, salt)
    try: 
        config = get_db_config()
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor(dictionary=True) # Se obtiene la info en modo diccionario
        query = ("SELECT * FROM users WHERE user = %s")
        cursor.execute(query, (user,))
        user_record = cursor.fetchone()
        cursor.close()
        if user_record:
            if bcrypt.check_password_hash(user_record['password'], password): #Compara los hashes para la autenticacion
                return render_template('result_data.html', mensaje= f"El usuario {user_record['user']} existe y su contraseña es valida")
            else:
                return render_template('result_data.html', mensaje= f"Usuario o contraseña invalidos")
    except Exception as e:
        mensaje = "Usuario no existente:" + str(e)
        return render_template('result_data_error.html', mensaje=mensaje)
        

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/website_info')
def website_info():
    return render_template('website_info.html')

@app.route('/capture_website_data', methods=['POST'])
def capture_website_data():
    user = request.form['user']
    password = request.form['password']
    website = request.form['website']

    try:
        config = get_db_config()
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        cursor.execute('INSERT INTO websites_info (website,user,password) VALUES(%s,%s,%s)',(website, user,password))
        connection.commit()
        cursor.close()
        connection.close()
        mensaje=f"La información para el sitio {website} fue agregada al password manager"
        return render_template('website_info_added.html',mensaje=mensaje)
    except Exception as e:
        mensaje="Error al insertar en la base de datos:" + str(e)
        return render_template('result data_error.html',mensaje=mensaje)

@app.route('/show_tables')
def show_tables():
    config = get_db_config()
    connection = mysql.connector.connect(**config)
    cursor = connection.cursor(dictionary=True) # Se obtiene la info en modo diccionario
    cursor.execute("SELECT * FROM websites_info")
    websites = cursor.fetchall() 
    connection.close()
    return render_template('tables.html', websites=websites)


if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

