# Tema de la base de datos para el proyecto del liibro de la app web con python/flask

## Descripción

- Estos pasos son para la creación de la base de datos, es una ligera desviación de lo que ese establece en el texto, pero se usa a manera de dar el sigumiento apropiado usando un contenedor de docker para crear la base de datos que se usara a lo largo de este aprendizaje.

- Como tal se creo un volumen, los pasos están acomodados por encabezados para dar un seguimiento apropiado al texto.


## Nombre del volumen

```bash
docker volume create myDB
```


Volumen: myDB (Persistencia de datos)

## Creación del contenedor
```bash
docker build -t my-sql:v1 .

docker build -f Dockerfile.mysql -t my-sql:v1 .

```
## Ejecución del contenedor
```bash
docker run -d -p 3306:3306 --name my-sql -v myDB:/var/lib/mysql my-sql:v1
```
## Conexión al contenedor de la base de datos
```bash
docker exec -it my-sql /bin/bash
```
## Conexión a mysql con el usuario root

En el docker file se genera un usuario root, lo cual no es ideal ya que no es seguro, pero de igual forma es lo que se usa.
```bash
mysql -u root -p
```

## Comandos usados en my SQL

Se genera un usario nuevo siguiendo la información del texto, esto a manera de dar seguimiento correcto.

```bash
CREATE USER 'lsi'@'%' IDENTIFIED BY 'lsi';
```
El usuario creado es de nombre *lsi* con la contraseña *lsi*.


De esta manera se le dan los persmisos necesarios para la creación indexación, inserción y manipulación de datos dentro de la base de datos.

```bash
GRANT CREATE, ALTER, DROP, INSERT, UPDATE, INDEX, DELETE, SELECT, REFERENCES, RELOAD on *.* TO 'lsi'@'%' WITH GRANT OPTION;
```

```bash
FLUSH PRIVILEGES;
```

## Conexión con usuario lsi


```bash
mysql -u lsi -p

Password lsi
```
Se hace el proces de flush a manera de remover el cache
```bash
FLUSH PRIVILEGES;
```
## Creación de base de datos

Se crea una base de datos de nombre login_user_data
```bash
CREATE DATABASE IF NOT EXISTS login_user_data;
```

Se hace uso de la base de login_user_data
```bash
USE login_user_data;
```
Se crea la table de la base de datos
```bash
CREATE TABLE IF NOT EXISTS clientes ( id INT AUTO_INCREMENT PRIMARY KEY, nombre VARCHAR(255) NOT NULL, apellido VARCHAR(255) NOT NULL, telefono VARCHAR(15) NOT NULL UNIQUE);
```
```bash
CREATE TABLE IF NOT EXISTS users ( id INT AUTO_INCREMENT PRIMARY KEY, user VARCHAR(255) NOT NULL UNIQUE, password VARCHAR(20) NOT NULL);
```

## Mostrar tablas
```bash
SHOW TABLES
```

## Creación con script

Ahora esto seria posible también con la creación de un script de la manera siguiente:

```bash
-- Crear la base de datos invitados 
CREATE DATABASE IF NOT EXISTS invitados; 
-- Usar la base de datos invitados 
USE invitados; 
-- Crear la tabla clientes con restricción de unicidad en el número de teléfono 
DROP TABLE IF EXISTS clientes; 
CREATE TABLE IF NOT EXISTS clientes ( 
    id INT AUTO_INCREMENT PRIMARY KEY, 
    nombre VARCHAR(255) NOT NULL, 
    apellido VARCHAR(255) NOT NULL, 
    telefono VARCHAR(15) NOT NULL UNIQUE 
);
-- Crear la tabla users con restricción de unicidad en el usuario
CREATE TABLE IF NOT EXISTS users ( 
    id INT AUTO_INCREMENT PRIMARY KEY, 
    user VARCHAR(255) NOT NULL UNIQUE, 
    password VARCHAR(20) NOT NULL
    );
```

La ejecución se haría a manera de este comando:

```bash
mysql -u lsi -p < script.sql
```

## Creación de los requirements 

```bash
pip freeze > requirements.txt
```

```bash
pip install -r requirements.txt
```


## Creacion del docker del backend con flask

```bash
docker build -t passmanager:v1 .
docker build -t passmanager:v1 -f Dockerfile.flask .    
```

## Ejecución del docker con flask

```bash
docker run -d -p 5000:5000 --name passmanager passmanager:v1
```

Ahora en el código se realizo el siguiente cambio:
```python
app.run(host='0.0.0.0', port=5000, debug=True)
```

## Creacion de NGINX

```bash
docker build -t nginx:v1 -f Dockerfile.nginx .   
```

```bash
docker run -d -p 8080:8080 --name nginx nginx:v1   

## NGINX Conf

```bash
/etc/nginx/conf.d/default.conf
```

## Desinstala los modulos de python

```powershell
pip freeze | ForEach-Object { pip uninstall -y $_ }

```