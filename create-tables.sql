-- this file contains the commands used to create the tables for the flights db
-- command to create the carriers
CREATE TABLE IF NOT EXISTS carriers (
    cid VARCHAR(7) PRIMARY KEY,
    name VARCHAR(83)
);

-- command for creating the months table
CREATE TABLE IF NOT EXISTS months (
    mid INT PRIMARY KEY,
    month VARCHAR(9)
);

-- command to create the weekdays table
CREATE  TABLE IF NOT EXISTS weekdays (
    did INT PRIMARY KEY,
    day_of_week VARCHAR(9)
);

-- command for creating the flights table
CREATE TABLE IF NOT EXISTS flights (
    fid INT PRIMARY KEY,
    month_id INT CHECK (month_id BETWEEN 1 AND 12) REFERENCES months(mid),
    day_of_month INT CHECK (day_of_month BETWEEN 1 AND 31),
    day_of_week_id INT CHECK (day_of_week_id BETWEEN 1 AND 7) REFERENCES weekdays(did),
    carrier_id VARCHAR(7) REFERENCES carriers(cid),
    flight_num INT,
    origin_city VARCHAR(34),
    origin_state VARCHAR(47),
    dest_city VARCHAR(34),
    dest_state VARCHAR(46),
    departure_delay INT, -- in minutes
    taxi_out INT, -- minutes
    arrival_delay INT, -- in minutes
    canceled INT, -- 1 means canceled
    actual_time INT, -- in mins
    distance INT, -- in miles
    capacity INT,
    price INT -- in $
);

-- command that will be used to create the users table
CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(20) PRIMARY KEY,
    password_hash VARBINARY(20) NOT NULL ,
    password_salt VARBINARY(20) NOT NULL ,
    balance INT NOT NULL
);

-- command to create the reservations table
CREATE TABLE IF NOT EXISTS reservations (
    rid INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(20) NOT NULL REFERENCES users(username),
    flight_type VARCHAR(10) NOT NULL,
    cost INT ,
    paid BOOLEAN NOT NULL,
    flight_1_id INT NOT NULL REFERENCES flights(fid),
    flight_2_id INT REFERENCES flights(fid)
);
