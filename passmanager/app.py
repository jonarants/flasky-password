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
    return bcrypt.generate_password_hash(password, 20).decode('utf-8')

def load_or_create_salt(call_type, user):
    config = get_db_config()
    connection = mysql.connector.connect(**config)
    cursor = connection.cursor()
    try:
      if call_type == "w":
          salt = os.urandom(16)
          salt_result = salt
      elif call_type == "r": # LA R O W yo las defino, así que no puede haber error de usuario
          cursor.execute('SELECT encryption_salt FROM users WHERE user = %s',(user))
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
        iterations=600_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@app.route('/register')
def login():
    return render_template('register.html')

@app.route('/logging_in', methods=['POST'])
def logging_in():
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
        return render_template ('resultado3.html' ,user=user)
    except Exception as e:
        mensaje = "Error al insertar a la base de datos:" + str(e)
        return render_template('resultado2.html', mensaje=mensaje)



@app.route('/logintest')
def logintest():
    return render_template('login_real.html')


@app.route('/login_validation', methods=['POST'])
def logging_in_test():
    user = request.form['user']
    password = request.form['password']
    salt = load_or_create_salt("r",user)
    key = get_key (password, salt)
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
                return render_template('resultado3.html', mensaje= f"El usuario {user_record['user']} existe y su contraseña es valida")
            else:
                return render_template('resultado3.html', mensaje= f"Usuario o contraseña invalidos")
    except Exception as e:
        mensaje = "Usuario no existente:" + str(e)
        return render_template('resultado2.html', mensaje=mensaje)
        

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/agregar_cita', methods=['POST'])
def agregar_cita():
    user = request.form['user']
    password = request.form['password']
    websites = request.form['websites']
    try:
        config = get_db_config()
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        cursor.execute('INSERT INTO websites_info (websites,user,password) VALUES(%s,%s,%s)',(websites, user,password))
        connection.commit()
        cursor.close()
        connection.close()
        return render_template('resultado.html',websites=websites,user=user,password=password)
    except Exception as e:
        mensaje="Error al insertar en la base de datos:" + str(e)
        return render_template('resultado2.html',mensaje=mensaje)
        
if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

