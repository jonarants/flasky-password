from flask import Flask, render_template, request
from flask_bcrypt import Bcrypt
import mysql.connector
import os
app = Flask(__name__)
bcrypt = Bcrypt (app)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
def get_db_config():
    return {
        'user': os.environ.get('MYSQL_USER'),
        'password': os.environ.get('MYSQL_PASSWORD'),
        'host': os.environ.get('MYSQL_HOST'),
        'port': os.environ.get('MYSQL_PORT'),
        'database': os.environ.get('MYSQL_DATABASE')
    }

def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/logging_in', methods=['POST'])
def logging_in():
    user = request.form['user']
    password = request.form['password']
    hashed_password = hash_password(password)
    #is_valid = bcrypt.check_password_hash(hashed_password, password)
    try: 
        config = get_db_config()
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        cursor.execute('INSERT INTO users (user,password) VALUES (%s,%s)',(user,hashed_password))
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
    hashed_password = hash_password(password)
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
    nombre = request.form['nombre']
    apellido = request.form['apellido']
    telefono = request.form['telefono']
    try:
        config = get_db_config()
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        cursor.execute('INSERT INTO clientes (nombre,apellido,telefono) VALUES(%s,%s,%s)',(nombre,apellido,telefono))
        connection.commit()
        cursor.close()
        connection.close()
        return render_template('resultado.html',telefono=telefono,nombre=nombre,apellido=apellido)
    except Exception as e:
        mensaje="Error al insertar en la base de datos:" + str(e)
        return render_template('resultado2.html',mensaje=mensaje)
        
if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

