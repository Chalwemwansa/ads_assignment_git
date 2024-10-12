-- commands that will load the data in the csv files into the tables in the db

LOAD DATA LOCAL INFILE 'C:\\ProgramData\\MySQL\\MySQL Server 9.0\\Uploads\\months.csv'
INTO TABLE months
FIELDS TERMINATED BY ',' 
OPTIONALLY ENCLOSED BY '"' 
LINES TERMINATED BY '\n';

LOAD DATA LOCAL INFILE 'C:\\ProgramData\\MySQL\\MySQL Server 9.0\\Uploads\\weekdays.csv'
INTO TABLE weekdays
FIELDS TERMINATED BY ',' 
OPTIONALLY ENCLOSED BY '"' 
LINES TERMINATED BY '\n';

LOAD DATA LOCAL INFILE 'C:\\ProgramData\\MySQL\\MySQL Server 9.0\\Uploads\\carriers.csv'
INTO TABLE carriers
FIELDS TERMINATED BY ',' 
OPTIONALLY ENCLOSED BY '"' 
LINES TERMINATED BY '\n';

LOAD DATA LOCAL INFILE 'C:\\ProgramData\\MySQL\\MySQL Server 9.0\\Uploads\\flights.csv'
INTO TABLE flights
FIELDS TERMINATED BY ',' 
OPTIONALLY ENCLOSED BY '"' 
LINES TERMINATED BY '\n';
