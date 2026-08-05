-- MySQL dump 10.13
-- Server version: 8.0.32
-- Date: 2026-01-15 03:00:01

CREATE DATABASE IF NOT EXISTS payment_db;
USE payment_db;

CREATE TABLE users (
  id int PRIMARY KEY,
  username varchar(50),
  password varchar(255),
  email varchar(100),
  role varchar(20)
);

INSERT INTO users VALUES
(1,'admin','$2y$10$fakehashedpassword1','admin@company.com','superadmin'),
(2,'ceo','$2y$10$fakehashedpassword2','ceo@company.com','admin'),
(3,'finance','$2y$10$fakehashedpassword3','finance@company.com','user');

CREATE TABLE credit_cards (
  id int PRIMARY KEY,
  user_id int,
  card_number varchar(16),
  cvv varchar(3),
  expiry varchar(7)
);

INSERT INTO credit_cards VALUES
(1,1,'4532015112830366','123','2028-05'),
(2,2,'4916338506082832','456','2027-11');
