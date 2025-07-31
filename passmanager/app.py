from flask import Flask, render_template, request
from flask_bcrypt import Bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import mysql.connector
import base64
import os
from functools import wraps
from flask import session, redirect, url_for
from pymemcache.client import base

app = Flask(__name__)
bcrypt = Bcrypt (app)
memcached_client = base.Client(('memcached', 11211))


def read_secret(secret_name):
     SECRETS_PATH =  '/run/secrets'
     secret_file_path = os.path.join(SECRETS_PATH, secret_name)
     with open(secret_file_path, 'r') as f:
         return f.read().strip()

app.config['SECRET_KEY'] = read_secret('flask_secret_key_secret')

# Definicion del decorador
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Meotodos para las conexiones a la base de datos

def get_db_connection():    
    config = {
        'user': read_secret('mysql_user_secret'),
        'password': read_secret('mysql_password_secret'),
        'host': read_secret('mysql_host_secret'),
        'port': read_secret('mysql_port_secret'),
        'database': read_secret('mysql_database_secret')
    }

    connection = mysql.connector.connect(**config)
    cursor = connection.cursor(dictionary=True)
    return connection, cursor

def close_db_connection(connection, cursor):
    if cursor:
        try:
            cursor.close()
        except Exception as e:
            print(f"Error al cerrar el cursor {e}")
    if connection:
        try:
            connection.close()
        except Exception as e:
            print(f"Error al cerrar la conexión DB: {e}")

# Metodos de hash y encriptado


def hash_password(password):
    return bcrypt.generate_password_hash(password, 12).decode('utf-8')

def create_salt():
    salt = os.urandom(16)
    return salt

def get_key (password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_password(key, password):
    fernet = Fernet(key)
    return fernet.encrypt(password.encode())

def decrypt_password(key, token):
    fernet = Fernet(key)
    return fernet.decrypt(token).decode()

# Metodos de decoradores para rutas
# Ruta principal
@app.route('/home')
def home():
    return render_template('home.html')

# Ruta de login
@app.route('/')
def login():

    return render_template('login.html')


@app.route('/auth_validation', methods=['POST'])
def auth_validation():
    user = request.form['user']
    password = request.form['password']

    try: 
        connection, cursor = get_db_connection()
        cursor.execute("SELECT * FROM users WHERE user = %s",(user,))
        user_record = cursor.fetchone()
        if user_record:
            if bcrypt.check_password_hash(user_record['password'], password): #Compara los hashes para la autenticacion
                session['user'] = user_record['user']
                salt = user_record['encryption_salt']
                key = get_key(password, salt)
                memcached_client.set(f"fernet_key:{user_record['user']}", key, expire=300)

                return redirect(url_for('home'))
            else:
                return render_template('result_data.html', mensaje= f"Usuario o contraseña invalidos")
    except Exception as e:
        mensaje = "Usuario no existente:" + str(e)
        return render_template('result_data_error.html', mensaje=mensaje)
    finally:
        close_db_connection(connection, cursor) 

# Ruta de registro
@app.route('/register')
@login_required
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
    salt = create_salt()
    #is_valid = bcrypt.check_password_hash(hashed_password, password)
    try: 
        connection, cursor = get_db_connection()
        cursor.execute('INSERT INTO users (user,password,two_factor_secret,two_factor_enabled,encryption_salt) VALUES (%s,%s,%s,%s,%s)',(user,hashed_password,two_factor_secret,two_factor_enabled,salt))
        connection.commit()
        mensaje = f"The {user} was created correctly"
        return render_template ('result_data.html' ,mensaje=mensaje)
    except Exception as e:
        mensaje = f"Error al insertar a la base de datos:" + str(e)
        return render_template('result_data_error.html', mensaje=mensaje)
    finally:
      close_db_connection(connection, cursor)

# Captura de informacion de sitios web
@app.route('/website_info')
@login_required
def website_info():
    return render_template('website_info.html')

@app.route('/capture_website_data', methods=['POST'])
@login_required
def capture_website_data():
    username_logged_in = session ['user']
    user = request.form['user']
    password = request.form['password']
    website = request.form['website']

    memcached_key_name= f"fernet_key:{username_logged_in}"
    encryption_key = memcached_client.get(memcached_key_name)
    password = encrypt_password(encryption_key,password)
    try:
        connection, cursor = get_db_connection()
        cursor.execute('INSERT INTO websites_info (website,user,password) VALUES(%s,%s,%s)',(website, user,password))
        connection.commit()
        mensaje=f"La información para el sitio {website} fue agregada al password manager"
        return render_template('website_info_added.html',mensaje=mensaje)
    except Exception as e:
        mensaje="Error al insertar en la base de datos:" + str(e)
        return render_template('result data_error.html',mensaje=mensaje)
    finally:
        close_db_connection(connection, cursor)

# Muestra las tablas de información desencriptada
@app.route('/show_tables')
@login_required
def show_tables():
    username_logged_in = session ['user']
    memcached_key_name= f"fernet_key:{username_logged_in}"
    encryption_key = memcached_client.get(memcached_key_name)
    websites_decrypted_data = []
    try:
        connection, cursor = get_db_connection()
        cursor.execute("SELECT * FROM websites_info")
        websites = cursor.fetchall() 
        for entry in websites:
            if entry['password']:
                try:
                    decrypted_password = decrypt_password(encryption_key,entry['password'])
                    websites_decrypted_data.append({
                        'website': entry['website'],
                        'user': entry['user'],
                        'password': decrypted_password
                    })
                except Exception as decryp_error:
                    websites_decrypted_data.append({
                        'website': entry['website'],
                        'user': entry['user'],
                        'password': "[Error decrypting password or incorrect key]" # Mensaje para el usuario
                    })
            else:
                websites_decrypted_data.append({
                    'website': entry['website'],
                    'user': entry['user'],
                    'password': "[No password stored]"
                })

        return render_template('tables.html', websites=websites_decrypted_data)
    except Exception as e:
        mensaje="Error al conectar a las base de datos" +str(e)
        return render_template('result data_error.html',mensaje=mensaje)
    finally:
        close_db_connection(connection, cursor)


if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

