CREATE DATABASE IF NOT EXISTS coffee_shop;
USE coffee_shop;

-- Users table
CREATE TABLE  users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(20) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_phone (phone)
);

CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    item_name VARCHAR(100) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    status ENUM('pending', 'completed', 'cancelled') DEFAULT 'pending',
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_status (status)
);


CREATE TABLE  login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_or_phone VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    success BOOLEAN DEFAULT FALSE,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email_phone (email_or_phone),
    INDEX idx_ip (ip_address),
    INDEX idx_time (attempt_time)
);

CREATE TABLE newsletter_subscribers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) UNIQUE NOT NULL,
    subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email (email)
);

CREATE TABLE sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (session_token),
    INDEX idx_user (user_id)
);

INSERT INTO users (name, email, phone, password) VALUES
('Admin User', 'admin@coffee.com', '+1111111111', 'admin123'),
('John Doe', 'john@test.com', '+2222222222', 'password'),
('Jane Smith', 'jane@test.com', '+3333333333', '123456'),
('Bob Wilson', 'bob@demo.com', '+4444444444', 'qwerty'),
('Alice Brown', 'alice@test.com', '+5555555555', 'letmein');


INSERT INTO orders (user_id, item_name, price, status) VALUES
(1, 'Cappuccino', 8.50, 'completed'),
(1, 'Espresso', 8.50, 'pending'),
(2, 'Chai Latte', 8.50, 'completed'),
(3, 'Macchiato', 8.50, 'pending');
