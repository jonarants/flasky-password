CREATE DATABASE IF NOT EXISTS login_user_data;
CREATE USER 'lsi'@'%' IDENTIFIED BY 'lsi';
GRANT ALL PRIVILEGES ON login_user_data.* TO 'lsi'@'%';
FLUSH PRIVILEGES;
USE login_user_data;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    two_factor_secret VARCHAR (255),
    two_factor_enabled BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS websites_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    websites VARCHAR(255) NOT NULL, 
    user VARCHAR(255) NOT NULL,     
    password VARCHAR(255) NOT NULL  
);