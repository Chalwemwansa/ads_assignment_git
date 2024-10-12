-- query for getting the direct route paths
SELECT 
    fid AS flight_1_id, 
    origin_city, 
    dest_city as final_destination, 
    price AS cost, 
    actual_time AS flight_time,
    day_of_month AS day,
    "direct" AS flight_type,
    carrier_id AS f1_carrier_id
FROM Flights
WHERE origin_city = 'New York NY'
AND dest_city = 'Los Angeles CA'
AND canceled = 0 
ORDER BY flight_time ASC, fid ASC
LIMIT 6;

/**
* "SELECT flight_num as number, fid AS flight_1_id, origin_city, dest_city as final_destination, price AS cost, actual_time AS flight_time, day_of_month AS day,"
        + "'direct' AS flight_type, carrier_id AS f1_carrier_id FROM Flights WHERE origin_city = ? AND dest_city = ? AND canceled = 0 AND day_of_month = ? ORDER BY flight_time ASC, fid ASC LIMIT ?"
*/
-- the queries used to retrieve data for indirect routes
SELECT DISTINCT
    f1.flight_num as 1_number,
    f2.flight_num as 2_number,
    f1.fid as flight_1_id,
    f2.fid as flight_2_id,
    f1.origin_city as 1_origin_city,
    f2.origin_city as middle_city,
    f1.dest_city as 1_final_destination,
    f2.dest_city as 2_final_destination,
    f1.price as 1_cost,
    f2.price as 2_cost,
    f1.actual_time as 1_flight_time,
    f2.actual_time as 2_flight_time,
    f1.day_of_month as 1_day,
    f2.day_of_month as 2_day,
    'indirect' as flight_type,
    f1.carrier_id as f1_carrier_id,
    f2.carrier_id as f2_carrier_id,
    f1.actual_time + f2.actual_time as flight_time
FROM Flights f1
INNER JOIN Flights f2 ON (
    f1.dest_city = f2.origin_city
    AND f1.canceled = 0
    AND f2.canceled = 0
    AND f1.day_of_month = 10
    AND f1.day_of_month = f2.day_of_month
)
WHERE f1.origin_city = 'Seattle WA' 
AND f2.dest_city = 'Boston MA'
ORDER BY flight_time ASC, flight_1_id ASC, flight_2_id ASC
LIMIT 5;
