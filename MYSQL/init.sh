#!/bin/bash

SECRETS_PATH="/run/secrets"

DB_USER=$(cat "${SECRETS_PATH}/mysql_user_secret")
DB_PASSWORD=$(cat "${SECRETS_PATH}/mysql_password_secret")
DB_NAME=$(cat "${SECRETS_PATH}/mysql_database_secret")
MYSQL_ROOT_PASSWORD=$(cat "${SECRETS_PATH}/mysql_root_password_file")
ADMIN_HASH=$(cat "${SECRETS_PATH}/mysql-admin-mysql-temp")
SALT_HASH=$(cat "${SECRETS_PATH}/mysql-salt")

mysql -u root -p"${MYSQL_ROOT_PASSWORD}" <<EOSQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;
CREATE USER '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'%';
FLUSH PRIVILEGES;
USE \`${DB_NAME}\`;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    two_factor_secret VARCHAR (255),
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    encryption_salt BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS websites_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    website VARCHAR(255) NOT NULL, 
    user VARCHAR(255) NOT NULL,     
    password BLOB NOT NULL,
    user_id VARCHAR(255) NOT NULL  
);

INSERT INTO users (user, password, two_factor_secret, two_factor_enabled, encryption_salt) VALUES (
    'admin',
    '${ADMIN_HASH}',
    NULL,
    FALSE,
    X'${SALT_HASH}'
);
EOSQL