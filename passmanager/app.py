from datetime import timedelta
from flask import Flask, render_template, request, session, redirect, url_for, flash, current_app
from flask_bcrypt import Bcrypt #
from functools import wraps
from pymemcache.client import base
from qr2fa.qr_2fa_utils import QR2FAUtils
import os
# Refactors
from secrets.read_secrets import ReadSecrets
from db.db_utils import DBUtils
from login.login_utils import LoginUtils
from crypto.crypto_utils import CryptoUtils
from flask_wtf.csrf import CSRFProtect


qr_2fa_utils = QR2FAUtils()
read_secrets = ReadSecrets()
db_utils = DBUtils(read_secrets)
crypto_utils = CryptoUtils()
login_utils = LoginUtils()

app = Flask(__name__)
csrf = CSRFProtect(app) 
crypto_utils.init_app(app)
bcrypt = Bcrypt (app)
memcached_client = base.Client(('memcached', 11211))

app.config.from_mapping(
    SECRET_KEY= read_secrets.get_secret('flask_secret_key_secret'), #Carga de secreto de app
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=60) # Manejo de session timeout
)



#CONSTANTS SONAR
LOGIN = 'login.html'
WEBSITE_INFO = 'website_info.html'
# Definicion del decorador befor_request que se usa para el timeout de sesiones

@app.before_request
def before_request():
    if 'user' in session:
        session.permanent = True
        session['user']
        memcached_key_name = f"fernet_key:{session['user']}"
        if memcached_client.get(memcached_key_name):
            memcached_client.touch(memcached_key_name, expire=60)
        else:
            return redirect(url_for('login'))

# Definicion del decorador de login necesario
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session['admin'] != True:
            flash("You don't have the right role to access this page.",'warning')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Metodos de decoradores para rutas

# Ruta del dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    message = request.args.get('message')
    return render_template('dashboard.html', message=message)

# Ruta de login/validacion del login/ruta principal
@app.route('/')
def login():
    if 'user' in session:
        memcached_client.delete(f"fernet_key:{session['user']}")
    session.pop('user', None)
    session.clear()
    return render_template(LOGIN)

@app.route('/login_validation', methods=['POST'])
def login_validation():
    user = request.form['user']
    password = request.form['password']
    connection = None
    cursor = None
    twofatoken = request.form['2fatoken']
    user_record = None
    try:
        connection, cursor = db_utils.connect()
        cursor.execute("SELECT * FROM users WHERE user = %s",(user,))
        user_record=cursor.fetchone()        
    except Exception as e:
        message = f"Error: {e}"
        return render_template(LOGIN, message = message)
    finally:
        db_utils.disconnect(connection, cursor)

    two_fa_secret=user_record['two_factor_secret']

    if not user_record:
        message = "Invalid user/password"
        return render_template(LOGIN, message = message)
    if not crypto_utils.validate_password(user_record['password'], password):
        message = "Invalid user/password"
        return render_template(LOGIN, message = message)
    
    
    session['user'] = user_record['user']
    session['admin'] = login_utils.user_auth_role(user_record) # Sets user role for views
    session.permanent = True
    user_encryption_key = user_record['encrypted_user_key']
    key_salt = user_record['key_salt']
    derivation_key = crypto_utils.get_key(password, key_salt)
    decrypted_user_key = crypto_utils.decrypt_derivation(derivation_key, user_encryption_key)
    memcached_client.set(f"fernet_key:{session['user']}", decrypted_user_key, expire=60)
    
    if two_fa_secret == None:
        return redirect(url_for('dashboard'))

    if qr_2fa_utils.validate_token(twofatoken, two_fa_secret):
        return redirect(url_for('dashboard'))
    else:
        message = "Invalid user/password"
        return render_template(LOGIN, message = message)

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
@is_admin
def register():
    message = request.args.get('message')
    qr_path = request.args.get('qr_path')
    return render_template('register.html', message=message, qr_path=qr_path)

@app.route('/register_user', methods=['POST'])
@login_required
@is_admin
def register_user():

    user = request.form['user']
    password = request.form['password']

    two_factor_enabled = request.form.get('two_factor_enabled')
    two_factor_enabled = (two_factor_enabled == "Enabled")
    if two_factor_enabled:
        two_factor_secret = qr_2fa_utils.create_secret_for_2fa() # Hace falta encryptarlo para almacenarlo en la BD
        base_path = os.path.dirname(os.path.abspath(__file__)) 
        basepath = os.path.join(base_path, 'static')
        uri_totp = qr_2fa_utils.generate_uri(two_factor_secret, user)
        qr_path = qr_2fa_utils.generate_uri_qrcode(uri_totp, basepath)
    else:
        two_factor_secret = None
    
    is_admin_enabled = request.form.get('is_admin_enabled')
    is_admin_enabled = (is_admin_enabled == "Enabled")
    
    hashed_password = crypto_utils.hash_password(password)
    user_encryption_key = crypto_utils.generate_fernet_key()
    key_salt = crypto_utils.create_salt()
    derivation_key = crypto_utils.get_key(password,key_salt)
    encrypted_user_key = crypto_utils.encrypt_derivation(derivation_key, user_encryption_key)

    try: 
        connection, cursor = db_utils.connect()
        cursor.execute('INSERT INTO users (user,password,two_factor_secret,two_factor_enabled,key_salt,encrypted_user_key, admin) VALUES (%s,%s,%s,%s,%s,%s,%s)',(user,hashed_password,two_factor_secret,two_factor_enabled,key_salt, encrypted_user_key,is_admin_enabled))
        connection.commit()
        message = f"The user: {user} Was created correctly"
        if two_factor_enabled:
            return redirect(url_for('register', message=message, qr_path=qr_path))
        else:
            return redirect(url_for('register', message=message))
    except Exception as e:
        message = f"Error creating the user: {e}"
        return redirect(url_for('dashboard', message=message))
    finally:
      db_utils.disconnect(connection, cursor)

# Administracion de usuarios
# Eliminar usuarios
@app.route('/manage_users', methods =['GET'])
@login_required
@is_admin
def get_manage_users():
    connection = None
    cursor = None
    users = []
    message = None
    connection, cursor = db_utils.connect()
    if request.method == 'GET':
        try:
            cursor.execute("SELECT id, user from users")
            users = cursor.fetchall()
            message = request.args.get('message')
            return render_template('manage_users.html', users=users, message=message)
        except Exception as e:
            message = f"No valid information found, error{e}"
            return render_template('manage_users.html', message=message)
        finally:
            db_utils.disconnect(connection,cursor)

@app.route('/manage_users', methods = ['POST'])
@login_required
@is_admin
def manage_users():
    connection = None
    cursor = None
    users = []
    message = None
    connection, cursor = db_utils.connect()
    users_to_delete = request.form.getlist('delete_users_ids')
    if not users_to_delete:
        message = "No users selected for deletion"
        return redirect(url_for('manage_users', message=message))
    else:
        try:
            users =','.join(['%s'] * len(users_to_delete))
            sql_query = f"DELETE FROM users WHERE user in ({users})"
            cursor.execute(sql_query, tuple(users_to_delete))
            connection.commit()
            message = f"Sucessfully deleted {len(users_to_delete)} user(s)."
            return redirect(url_for('manage_users', message=message))
        except Exception as e:
            message = f"Error deleting users {e}"
            if connection:
                connection.rollback()
            return redirect(url_for('manage_users', message=message))
        finally:
            db_utils.disconnect(connection, cursor)

@app.route('/reset_password', methods=['GET'])
@login_required
def get_reset_password():
    message = request.args.get('message')
    return render_template('reset_password.html',message=message)


@app.route('/reset_password', methods=['POST'])
@login_required
def reset_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_new_password = request.form['confirm_new_password']
    current_user = session['user']
    try:
        connection, cursor = db_utils.connect()
        cursor.execute("SELECT * FROM users WHERE user = %s",(current_user,))
        user_record = cursor.fetchone()
        if user_record:
            if crypto_utils.validate_password(user_record['password'], current_password) and (new_password == confirm_new_password):

                #Desencripta la clave vieja
                derivation_key_old = crypto_utils.get_key(current_password, user_record['key_salt'])
                decrypted_user_key = crypto_utils.decrypt_derivation (derivation_key_old, user_record['encrypted_user_key'])

                new_hashed_password = crypto_utils.hash_password(new_password)
                new_key_salt = crypto_utils.create_salt()
                derivation_key_new = crypto_utils.get_key(new_password,new_key_salt)
                encrypted_user_key_new = crypto_utils.encrypt_derivation(derivation_key_new, decrypted_user_key)
                cursor.execute("""
                    UPDATE users
                    SET password = %s,
                        key_salt = %s,
                        encrypted_user_key = %s
                    WHERE user = %s 
                """, (new_hashed_password, new_key_salt, encrypted_user_key_new, current_user))
                connection.commit()
                message = f'Password changed for user {current_user}'
                return redirect(url_for('dashboard', message=message))
    except Exception as e:
        message = f"Error when updating the password:{e}"
        return redirect(url_for('reset_password', message=message))
    finally:
        db_utils.disconnect(connection, cursor)
        
@app.route('/website_info', methods = ['GET'])
@login_required
def get_website_info():
        message = request.args.get('message')
        return render_template(WEBSITE_INFO, message=message)

# Captura de informacion de sitios web

@app.route('/website_info', methods=['POST'])
@login_required
def website_info():
    username_logged_in = session['user']
    user = request.form['user']
    password = request.form['password']
    website = request.form['website']
    memcached_key_name= f"fernet_key:{username_logged_in}"
    encryption_key = memcached_client.get(memcached_key_name)
    password = crypto_utils.encrypt_password(encryption_key,password)
    try:
        connection, cursor = db_utils.connect()
        cursor.execute('INSERT INTO websites_info (website,user,password,owner) VALUES(%s,%s,%s,%s)',(website, user, password, username_logged_in))
        connection.commit()
        message=f"The website for {website} was added successfully"
        return render_template(WEBSITE_INFO,message=message)
    except Exception as e:
        message="Error when trying to insert the information into the table:" + str(e)
        return render_template(WEBSITE_INFO,message=message)
    finally:
        db_utils.disconnect(connection, cursor)

# Muestra las tablas de información desencriptada
@app.route('/show_tables')
@login_required
def show_tables():
    message = request.args.get('message')
    username_logged_in = session ['user']
    memcached_key_name= f"fernet_key:{username_logged_in}"
    encryption_key = memcached_client.get(memcached_key_name)
    websites_decrypted_data = []
    try:
        connection, cursor = db_utils.connect()
        cursor.execute("SELECT * FROM websites_info WHERE owner = %s",(username_logged_in,))
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
                        'owner': entry['owner']
                    })
                except Exception as decrypt_error:
                    websites_decrypted_data.append({
                        'id': entry['id'],
                        'website': entry['website'],
                        'user': entry['user'],
                        'password': f"[Error decrypting password or incorrect key {decrypt_error}]", # message para el usuario
                        'owner': entry['owner']
                    })
            else:
                websites_decrypted_data.append({
                    'id': entry['id'],
                    'website': entry['website'],
                    'user': entry['user'],
                    'password': "[No password stored]",
                    'owner': entry['owner']
                })

        return render_template('show_tables.html', websites=websites_decrypted_data)
    except Exception as e:
        message="Error al conectar a las base de datos" +str(e)
        return redirect(url_for('show_tables',message=message))
    finally:
        db_utils.disconnect(connection, cursor)

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) #Pending to change

