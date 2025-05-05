from flask import Flask, render_template, request
import mysql.connector
app = Flask(__name__)
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/agregar_cita/', methods=['POST'])
def agregar_cita():
    if request.method == 'POST':
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        telefono = request.form['telefono']
        try:
            config = { 'user':'lsi','password':'lsi','host':'db','port':'3306','database':'invitados'}
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

