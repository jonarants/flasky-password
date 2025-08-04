from datetime import timedelta
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_bcrypt import Bcrypt #
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet #
import mysql.connector
import base64
import os
from functools import wraps
from pymemcache.client import base

# Refactors
from secrets.read_secrets import ReadSecrets
from db.db_utils import DBUtils
from crypto.crypto_utils import CryptoUtils

read_secrets = ReadSecrets()
db_utils = DBUtils(read_secrets)
crypto_utils = CryptoUtils()

app = Flask(__name__)
crypto_utils.init_app(app)
bcrypt = Bcrypt (app)
memcached_client = base.Client(('memcached', 11211))
app.config['SECRET_KEY'] = read_secrets.get_secret('flask_secret_key_secret') # Lectura del secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=60) # Manejo de session timeout

# Definicion del decorador befor_request que se usa para el timeout de sesiones

@app.before_request
def before_request():
    if 'user' in session:
        session.permanent = True
        session['user']

# Definicion del decorador de login necesario
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Metodos de decoradores para rutas

# Ruta del dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Ruta de login/validacion del login/ruta principal
@app.route('/')
def login():
    if 'user' in session:
        memcached_client.delete(f"fernet_key:{session['user']}")
    session.pop('user', None)
    session.clear()
    return render_template('login.html')

@app.route('/login_validation', methods=['POST'])
def login_validation():
    user = request.form['user']
    password = request.form['password']

    try: 
        connection, cursor = db_utils.connect()
        cursor.execute("SELECT * FROM users WHERE user = %s",(user,))
        user_record = cursor.fetchone()
        if user_record:
            if crypto_utils.validate_password(user_record['password'], password): #Compara los hashes para la autenticacion
                session['user'] = user_record['user']
                session.permanent = True
                salt = user_record['encryption_salt']
                key = crypto_utils.get_key(password, salt)
                memcached_client.set(f"fernet_key:{session['user']}", key, expire=300)
                return redirect(url_for('dashboard'))
            else:
                return render_template('login_error.html', message= f"Usuario o contraseña invalidos")
        else:
            return render_template('login_error.html', message= f"Usuario o contraseña invalidos")    
    except Exception as e:
        message = "Error:" + str(e)
        return render_template('login_error.html', message=message)
    finally:
        db_utils.disconnect(connection, cursor) 

# Metodo de logout

@app.route('/logout')
def logout():
    if 'user' in session:
        memcached_client.delete(f"fernet_key:{session['user']}")
    session.pop('user', None)
    session.clear()

    return render_template('logout.html')

# Ruta de registro
@app.route('/register')
@login_required
def register():
    return render_template('register.html')

@app.route('/register_user', methods=['POST'])
@login_required
def register_user():

    user = request.form['user']
    password = request.form['password']
    two_factor_secret = "placeholder data"#request.form['two_factor_secret']
    two_factor_enabled = request.form.get('two_factor_enabled')
    two_factor_enabled = (two_factor_enabled == "Enabled")
    hashed_password = crypto_utils.hash_password(password)
    salt = crypto_utils.create_salt()
    #is_valid = bcrypt.check_password_hash(hashed_password, password)
    try: 
        connection, cursor = db_utils.connect()
        cursor.execute('INSERT INTO users (user,password,two_factor_secret,two_factor_enabled,encryption_salt) VALUES (%s,%s,%s,%s,%s)',(user,hashed_password,two_factor_secret,two_factor_enabled,salt))
        connection.commit()
        message = f"The {user} was created correctly"
        return render_template ('result_data.html', message=message)
    except Exception as e:
        message = f"Error al insertar a la base de datos:" + str(e)
        return render_template('result_data.html', message=message)
    finally:
      db_utils.disconnect(connection, cursor)

# Administracion de usuarios

@app.route('/manage_users')
@login_required
def manage_users():
    try:
        connection, cursor = db_utils.connect()
        cursor.execute("SELECT id, user FROM users")
        users = cursor.fetchall()
    except Exception as e:
        print(f"Not valid information found error {e}")
    finally:
        db_utils.disconnect(connection, cursor)
            
    return render_template('manage_users.html', users = users)

@app.route('/delete_selected_users', methods=['POST'])
@login_required
def delete_selected_users():
    if request.method == 'POST':
        users_to_delete_ids = request.form.getlist('delete_user_ids')
        if not users_to_delete_ids:
            flash("No users selected for deletion.", 'info')
            return redirect(url_for('manage_users'))
        try:
            connection, cursor = db_utils.connect()
            user_list = ','.join(['%s'] * len (users_to_delete_ids))
            sql_query = f"DELETE FROM users WHERE user IN ({user_list})"
            cursor.execute(sql_query, tuple(users_to_delete_ids))
            sql_query = f"DELETE FROM websites_info WHERE user_id IN ({user_list})"
            cursor.execute(sql_query, tuple(users_to_delete_ids))
            connection.commit()
            flash(f"Successfully deleted {len(users_to_delete_ids)} user(s).", 'success')
        except Exception as e:
            flash(f"Error deleting users: {e}","error")
            if connection:
                connection.rollback()
            print(f"Error al eliminar usuarios {e}")
        finally:
            if connection and cursor:
                db_utils.disconnect(connection, cursor)    
    return redirect(url_for('manage_users'))


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
    password = crypto_utils.encrypt_password(encryption_key,password)
    try:
        connection, cursor = db_utils.connect()
        cursor.execute('INSERT INTO websites_info (website,user,password,user_id) VALUES(%s,%s,%s,%s)',(website, user, password, username_logged_in))
        connection.commit()
        message=f"The website for {website} was added successfully"
        return render_template('website_info_added.html',message=message)
    except Exception as e:
        message="Error when trying to insert the information into the table:" + str(e)
        return render_template('result_data.html',message=message)
    finally:
        db_utils.disconnect(connection, cursor)

# Muestra las tablas de información desencriptada
@app.route('/show_tables')
@login_required
def show_tables():
    username_logged_in = session ['user']
    memcached_key_name= f"fernet_key:{username_logged_in}"
    encryption_key = memcached_client.get(memcached_key_name)
    websites_decrypted_data = []
    try:
        connection, cursor = db_utils.connect()
        cursor.execute("SELECT * FROM websites_info WHERE user_id = %s",(username_logged_in,))
        websites = cursor.fetchall() 
        for entry in websites:
            if entry['password']:
                try:
                    decrypted_password = crypto_utils.decrypt_password(encryption_key,entry['password'])
                    websites_decrypted_data.append({
                        'id': entry['id'],
                        'website': entry['website'],
                        'user': entry['user'],
                        'password': decrypted_password,
                        'user_id': entry['user_id']
                    })
                except Exception as decrypt_error:
                    websites_decrypted_data.append({
                        'id': entry['id'],
                        'website': entry['website'],
                        'user': entry['user'],
                        'password': "[Error decrypting password or incorrect key]", # message para el usuario
                        'user_id': entry['user_id']
                    })
            else:
                websites_decrypted_data.append({
                    'id': entry['id'],
                    'website': entry['website'],
                    'user': entry['user'],
                    'password': "[No password stored]",
                    'user_id': entry['user_id']
                })

        return render_template('show_tables.html', websites=websites_decrypted_data)
    except Exception as e:
        message="Error al conectar a las base de datos" +str(e)
        return render_template('result_data.html',message=message)
    finally:
        db_utils.disconnect(connection, cursor)

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

