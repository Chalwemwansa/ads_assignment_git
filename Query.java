package edu.unza.cs;

import java.io.*;
import java.sql.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.xml.bind.*;

import com.mysql.cj.protocol.Resultset;
import com.mysql.cj.xdevapi.PreparableStatement;

/**
 * Runs queries against a back-end database
 */
public class Query {
  // DB Connection
  private Connection conn;

  // make a variable that will hold the username for the user that is currently logged in
  String user = null;

  // the duration for the flight
  int duration = 0;

  // the list of reservations the user searches for
  List<Map<String, Object>> flights = new ArrayList<>();

  // Password hashing parameter constants
  private static final int HASH_STRENGTH = 65536;
  private static final int KEY_LENGTH = 128;

  // Canned queries
  private static final String CHECK_FLIGHT_CAPACITY = "SELECT capacity FROM Flights WHERE fid = ?";
  private PreparedStatement checkFlightCapacityStatement;

  // TODO: YOUR CODE HERE

  /**
   * Establishes a new application-to-database connection. Uses the
   * dbconn.properties configuration settings
   * 
   * @throws IOException
   * @throws SQLException
   */
  public void openConnection() throws IOException, SQLException {
    // Connect to the database with the provided connection configuration
    Properties configProps = new Properties();
    configProps.load(new FileInputStream("dbconn.properties"));
    String serverURL = configProps.getProperty("hw1.server_url");
    String dbName = configProps.getProperty("hw1.database_name");
    String adminName = configProps.getProperty("hw1.username");
    String password = configProps.getProperty("hw1.password");
    String connectionUrl = String.format("jdbc:mysql://%s:3306/%s?user=%s&password=%s", serverURL,
        dbName, adminName, password);
    conn = DriverManager.getConnection(connectionUrl);

    // By default, automatically commit after each statement
    conn.setAutoCommit(true);

    // By default, set the transaction isolation level to serializable
    conn.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
  }

  /**
   * Closes the application-to-database connection
   */
  public void closeConnection() throws SQLException {
    conn.close();
  }

  /**
   * Clear the data in any custom tables created.
   * 
   * WARNING! Do not drop any tables and do not clear the flights table.
   */
  public void clearTables() {
    try {
        conn.setAutoCommit(false);
        // Clear custom tables, excluding flights
        conn.createStatement().executeUpdate("DELETE FROM Reservations");
        conn.createStatement().executeUpdate("DELETE FROM Users");

        // Reset auto-increment values for the Reservations and Users tables
        conn.createStatement().executeUpdate("ALTER TABLE Reservations AUTO_INCREMENT = 1");
        conn.commit();
        conn.setAutoCommit(true);
    } catch (Exception e) {
      try {
        conn.rollback();
        conn.setAutoCommit(true);
      } catch (Exception er) {

      }
      e.printStackTrace();
    }
  }

  /*
   * prepare all the SQL statements in this method.
   */
  public void prepareStatements() throws SQLException {
    checkFlightCapacityStatement = conn.prepareStatement(CHECK_FLIGHT_CAPACITY);
    // your code comes here
  }

  /**
   * Takes a user's username and password and attempts to log the user in.
   *
   * @param username user's username
   * @param password user's password
   *
   * @return If someone has already logged in, then return "User already logged
   *         in\n" For all other errors, return "Login failed\n". Otherwise,
   *         return "Logged in as [username]\n".
   */
  public String transaction_login(String username, String password) {
    try { 
      if (this.user != null && this.user.equals(username)) {
        return String.format("user %s already logged in\n", username);
      }
      PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
      stmt.setString(1, username);
      ResultSet userDetails = stmt.executeQuery();
      if (userDetails.next()) {
        byte[] storedSalt = userDetails.getBytes("password_salt");
        byte[] storedPassword = userDetails.getBytes("password_hash");
        // Specify the hash parameters
        KeySpec spec = new PBEKeySpec(password.toCharArray(), storedSalt, HASH_STRENGTH, KEY_LENGTH);

        // Generate the hash
        SecretKeyFactory factory = null;
        byte[] hash = null;
        try {
          factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
          hash = factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
          throw new IllegalStateException();
        }
        if (Arrays.equals(hash, storedPassword)) {
          this.user = username;
          return String.format("Logged in as %s\n", username);
        }
      }
      return String.format("Failed to log in user %s\n", username);
    } catch (SQLException e) 
    {
      return "Login failed\n";}
  }

  /**
   * Implement the create user function.
   *
   * @param username   new user's username. User names are unique the system.
   * @param password   new user's password.
   * @param initAmount initial amount to deposit into the user's account, should
   *                   be >= 0 (failure otherwise).
   *
   * @return either "Created user {@code username}\n" or "Failed to create user\n"
   *         if failed.
   */
  public String transaction_createCustomer(String username, String password, int initAmount) {
    
    // Generate a random cryptographic salt
    SecureRandom random = new SecureRandom();
    byte[] salt = new byte[16];
    random.nextBytes(salt);

    // Specify the hash parameters
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_STRENGTH, KEY_LENGTH);

    // Generate the hash
    SecretKeyFactory factory = null;
    byte[] hash = null;
    try {
      factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      hash = factory.generateSecret(spec).getEncoded();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
      throw new IllegalStateException(); 
    }

    // writing the prepared statement
    try {
      conn.setAutoCommit(false);
      PreparedStatement stmt = conn.prepareStatement("INSERT INTO users VALUES (?, ?, ?, ?)");
      stmt.setString(1, username);
      stmt.setBytes(2, hash);
      stmt.setBytes(3, salt);
      stmt.setInt(4, initAmount);
      // execute the stmt
      stmt.executeUpdate();
      conn.commit();
      conn.setAutoCommit(true);
      return "Created user " + username + "\n";
    } catch (SQLException e) {
      try {
        conn.rollback();
        conn.setAutoCommit(true);
      } catch (Exception er) {

      }
      return "Failed to create user\n"; }
    
  }

  /**
   * Implement the search function.
   *
   * Searches for flights from the given origin city to the given destination
   * city, on the given day of the month. If {@code directFlight} is true, it only
   * searches for direct flights, otherwise is searches for direct flights and
   * flights with two "hops." Only searches for up to the number of itineraries
   * given by {@code numberOfItineraries}.
   *
   * The results are sorted based on total flight time.
   *
   * @param originCity
   * @param destinationCity
   * @param directFlight        if true, then only search for direct flights,
   *                            otherwise include indirect flights as well
   * @param dayOfMonth
   * @param numberOfItineraries number of itineraries to return
   *
   * @return If no itineraries were found, return "No flights match your
   *         selection\n". If an error occurs, then return "Failed to search\n".
   *
   *         Otherwise, the sorted itineraries printed in the following format:
   *
   *         Itinerary [itinerary number]: [number of flights] flight(s), [total
   *         flight time] minutes\n [first flight in itinerary]\n ... [last flight
   *         in itinerary]\n
   *
   *         Each flight should be printed using the same format as in the
   *         {@code Flight} class. Itinerary numbers in each search should always
   *         start from 0 and increase by 1.
   *
   * @see Flight#toString()
   */
  public String transaction_search(String originCity, String destinationCity, boolean directFlight, int dayOfMonth,
      int numberOfItineraries) {
    try {
      PreparedStatement stmt = conn.prepareStatement("SELECT flight_num as number, capacity, fid AS flight_1_id, origin_city, dest_city as final_destination, price AS cost, actual_time AS flight_time, day_of_month AS day,"
        + "'direct' AS flight_type, carrier_id AS f1_carrier_id FROM Flights WHERE origin_city = ? AND dest_city = ? AND canceled = 0 AND day_of_month = ? ORDER BY flight_time ASC, fid ASC LIMIT ?");
      stmt.setString(1, originCity);
      stmt.setString(2, destinationCity);
      stmt.setInt(3, dayOfMonth);
      stmt.setInt(4, numberOfItineraries);
      ResultSet result = stmt.executeQuery();
      String retn = "";
      int ids = 0;
      this.flights.clear();
      while (result.next()) {
        Map<String, Object> flight = new HashMap<>();
        
        flight.put("f1_capacity", result.getInt("capacity"));
        flight.put("itinerary_id", ids);
        flight.put("flight_1_id", result.getInt("flight_1_id"));
        flight.put("cost", result.getInt("cost"));
        flight.put("flight_time", result.getInt("flight_time"));
        flight.put("flight_type", result.getString("flight_type"));
        this.flights.add(flight);  // Add the flight map to the array (List)
        String out = String.format("Itinerary %d: 1 flight(s), %d minutes\nID: %d Day: %d Carrier: %s Number: %d Origin: %s Dest: %s Duration: %d Capacity: %d Price: %d",
          ids, flight.get("flight_time"), flight.get("flight_1_id"), result.getInt("day"), result.getString("f1_carrier_id"), result.getInt("number"), result.getString("origin_city"), result.getString("final_destination"),
          flight.get("flight_time"), flight.get("f1_capacity"), flight.get("cost"));
        retn += out + "\n";
        ids += 1;
      }
      if ((!directFlight) && (this.flights.size() < numberOfItineraries)) {
        String quer = "SELECT DISTINCT "
          + "f1.flight_num as 1_number,"
          + "f2.flight_num as 2_number,"
          + "f1.fid as flight_1_id,"
          + "f2.fid as flight_2_id,"
          + "f1.origin_city as origin_city,"
          + "f2.origin_city as middle_city,"
          + "f2.dest_city as final_destination,"
          + "f1.price as 1_cost,"
          + "f1.capacity as f1_capacity,"
          + "f2.capacity as f2_capacity,"
          + "f2.price as 2_cost,"
          + "f1.actual_time as 1_flight_time,"
          + "f2.actual_time as 2_flight_time,"
          + "f1.day_of_month as day,"
          + "'indirect' as flight_type,"
          + "f1.carrier_id as f1_carrier_id,"
          + "f2.carrier_id as f2_carrier_id,"
          + "f1.actual_time + f2.actual_time as flight_time "
          + "FROM Flights f1 "
          + "INNER JOIN Flights f2 ON ("
          +   "f1.dest_city = f2.origin_city "
          +   "AND f1.canceled = 0 "
          +   "AND f2.canceled = 0 "
          +   "AND f1.day_of_month = ? "
          +   "AND f1.day_of_month = f2.day_of_month) "
          + "WHERE f1.origin_city = ? "
          + "AND f2.dest_city = ? "
          + "ORDER BY flight_time ASC, flight_1_id ASC, flight_2_id ASC "
          + "LIMIT ?";
        PreparedStatement stmt_2 = conn.prepareStatement(quer);
        stmt_2.setInt(1, dayOfMonth);
        stmt_2.setString(2, originCity);
        stmt_2.setString(3, destinationCity);
        stmt_2.setInt(4, numberOfItineraries - this.flights.size());
        ResultSet results_2 = stmt_2.executeQuery();
        while(results_2.next()) {
          Map<String, Object> flight = new HashMap<>(); // new map to put the results
          
          flight.put("f1_capacity", results_2.getInt("f1_capacity"));
          flight.put("f2_capacity", results_2.getInt("f2_capacity"));
          flight.put("itinerary_id", ids);
          flight.put("flight_1_id", results_2.getInt("flight_1_id"));
          flight.put("flight_2_id", results_2.getInt("flight_2_id"));
          flight.put("cost", results_2.getInt("1_cost") + results_2.getInt("2_cost"));
          flight.put("flight_time", results_2.getInt("flight_time"));
          flight.put("flight_type", results_2.getString("flight_type"));
          this.flights.add(flight);  // Add the flight map to the array (List)

          String out1 = String.format("ID: %d Day: %d Carrier: %s Number: %d Origin: %s Dest: %s Duration: %d Capacity: %d Price: %d",
            flight.get("flight_1_id"), results_2.getInt("day"), results_2.getString("f1_carrier_id"), results_2.getInt("1_number"), results_2.getString("origin_city"), results_2.getString("middle_city"),
            results_2.getInt("1_flight_time"), results_2.getInt("f1_capacity"), results_2.getInt("1_cost"));
          
          String out2 = String.format("ID: %d Day: %d Carrier: %s Number: %d Origin: %s Dest: %s Duration: %d Capacity: %d Price: %d",
            flight.get("flight_2_id"), results_2.getInt("day"), results_2.getString("f2_carrier_id"), results_2.getInt("2_number"), results_2.getString("middle_city"), results_2.getString("final_destination"),
            results_2.getInt("2_flight_time"), results_2.getInt("f2_capacity"), results_2.getInt("2_cost"));
          String out = String.format("Itinerary %d: 2 flight(s), %d minutes\n%s\n%s", ids, flight.get("flight_time"), out1, out2);
          retn += out + "\n";
          ids += 1;
        }
      }
      return retn;
    } catch (SQLException e) {
      return "no itineraries\n"; }
  }

  /**
   * Implements the book itinerary function.
   *
   * @param itineraryId ID of the itinerary to book. This must be one that is
   *                    returned by search in the current session.
   *
   * @return If the user is not logged in, then return "Cannot book reservations,
   *         not logged in\n". If try to book an itinerary with invalid ID, then
   *         return "No such itinerary {@code itineraryId}\n". If the user already
   *         has a reservation on the same day as the one that they are trying to
   *         book now, then return "You cannot book two flights in the same
   *         day\n". For all other errors, return "Booking failed\n".
   *
   *         And if booking succeeded, return "Booked flight(s), reservation ID:
   *         [reservationId]\n" where reservationId is a unique number in the
   *         reservation system that starts from 1 and increments by 1 each time a
   *         successful reservation is made by any user in the system.
   */
  public String transaction_book(int itineraryId) {
    if (this.user == null) {
      return "Login first to book\n";
    }
    PreparedStatement stmt = null;
    ResultSet rs = null;
    int retries = 5;

    while (retries >= 0) {
      try {
      String quer;
      if (this.flights.isEmpty()) {
        return "Invalid Itinerary number use search command to see valid itinerary numbers\n";
      }
      Map<String, Object> itinerary = this.flights.get(itineraryId);

      conn.setAutoCommit(false);
      // Combine both flight checks into a single query
      String sql = "SELECT " +
             "(SELECT COUNT(flight_1_id) FROM reservations WHERE flight_1_id = ? FOR UPDATE) as flight1_booked, " +
             "(SELECT COUNT(flight_2_id) FROM reservations WHERE flight_2_id = ? FOR UPDATE) as flight2_booked";

      stmt = conn.prepareStatement(sql);
      stmt.setInt(1, (int) itinerary.get("flight_1_id"));
      stmt.setInt(2, itinerary.get("flight_2_id") != null ? (int) itinerary.get("flight_2_id") : 0);

      rs = stmt.executeQuery();

      if (rs.next()) {
        int flight1Booked = rs.getInt("flight1_booked");
        int flight2Booked = rs.getInt("flight2_booked");

        // Check capacity for flight 1
        if ((int) itinerary.get("f1_capacity") - flight1Booked <= 0) {
          conn.rollback();
          return "Booking failed\n";
        }

        // Check capacity for flight 2 (if applicable)
        if (itinerary.get("flight_2_id") != null && (int) itinerary.get("f2_capacity") - flight2Booked <= 0) {
          conn.rollback();
          return "Booking failed\n";
        }
      }

      if (itinerary.get("flight_2_id") != null) { // 2 flights
        quer = "INSERT INTO reservations (username, flight_type, paid, duration, cost, flight_1_id, flight_2_id) VALUES (?, ?, ?, ?, ?, ?, ?)";
      } else {
        quer = "INSERT INTO reservations (username, flight_type, paid, duration, cost, flight_1_id) VALUES (?, ?, ?, ?, ?, ?)";
      }
      
      stmt = conn.prepareStatement(quer, Statement.RETURN_GENERATED_KEYS);
      stmt.setString(1, this.user);
      stmt.setString(2, (String) itinerary.get("flight_type"));
      stmt.setBoolean(3, false);
      stmt.setInt(4, (int) itinerary.get("flight_time"));
      stmt.setInt(5, (int) itinerary.get("cost"));
      stmt.setInt(6, (int) itinerary.get("flight_1_id"));
      if (itinerary.get("flight_2_id") != null) {       
        stmt.setInt(7, (int) itinerary.get("flight_2_id"));
      }
      stmt.executeUpdate();
      conn.commit();
      conn.setAutoCommit(true);
      long reservationId = 0;
      rs = stmt.getGeneratedKeys();
      if (rs.next()) {
        reservationId = rs.getLong(1);
      }
      return "Booked flight(s), reservation ID: " + reservationId +"\n";
    }
    catch (SQLException e) {
        if (e.getSQLState().equals("40001")) {  // Deadlock detected
          try {
            conn.rollback();
            retries--;
          } catch (SQLException er) {
            return "Booking failed\n";
          }
        } else {
          return "Booking failed\n";
        }
        
    } finally {
        try {
            if (rs != null) rs.close();  // Close ResultSet
            if (stmt != null) stmt.close();  // Close PreparedStatement
            conn.setAutoCommit(true);  // Restore auto-commit mode
        } catch (SQLException closeEx) {
          return "Booking failed\n";
            // Handle exceptions during closing resources, if necessary
        }
    }
    }
    return "Booking failed\n";
  }

  /**
   * Implements the pay function.
   *
   * @param reservationId the reservation to pay for.
   *
   * @return If no user has logged in, then return "Cannot pay, not logged in\n"
   *         If the reservation is not found / not under the logged in user's
   *         name, then return "Cannot find unpaid reservation [reservationId]
   *         under user: [username]\n" If the user does not have enough money in
   *         their account, then return "User has only [balance] in account but
   *         itinerary costs [cost]\n" For all other errors, return "Failed to pay
   *         for reservation [reservationId]\n"
   *
   *         If successful, return "Paid reservation: [reservationId] remaining
   *         balance: [balance]\n" where [balance] is the remaining balance in the
   *         user's account.
   */
  public String transaction_pay(int reservationId) {
    try {
      if (this.user == null) {
        return "Login first to pay\n";
      }
      PreparedStatement stmt = conn.prepareStatement("SELECT username, paid, cost FROM reservations WHERE rid = ?");
      stmt.setInt(1, reservationId);
      ResultSet rst = stmt.executeQuery();
      if (rst.next()) {
        if (rst.getBoolean("paid")) {
          return "Reservation " + reservationId + "has already been paid for\n";
        }
        if (!this.user.equals(rst.getString("username"))) {
          return "Cannot find unpaid reservation " + reservationId + " under user: " + this.user +"\n";
        }
        PreparedStatement smtU = conn.prepareStatement("SELECT balance FROM users WHERE username = ?");
        smtU.setString(1, this.user);
        ResultSet balance = smtU.executeQuery();
        if (balance.next()) {
          if (balance.getInt("balance") < rst.getInt("cost")) {
            return "Insufficient Credit in user account\n";
          } else {
            conn.setAutoCommit(false);
            PreparedStatement deduct = conn.prepareStatement("UPDATE users SET balance = ? WHERE username = ?");
            deduct.setInt(1, balance.getInt("balance") - rst.getInt("cost"));
            deduct.setString(2, this.user);
            deduct.executeUpdate();
            PreparedStatement paid = conn.prepareStatement("UPDATE reservations SET paid = ? WHERE rid = ?");
            paid.setBoolean(1, true);
            paid.setInt(2, reservationId);
            paid.executeUpdate();
            conn.commit();
            conn.setAutoCommit(true);
            return "Payment for reservation " + reservationId + " was successful\n";
          }
        }
      }else {return "Cannot find unpaid reservation " + reservationId + " under user: " + this.user +"\n";}
      return "Payment for reservation " + reservationId + " successful\n";
    } catch (SQLException e) {
      try {
        conn.rollback();
        conn.setAutoCommit(true);
      } catch (Exception er) {}
      return "Failed to pay for reservation " + reservationId + "\n";
    }
  }

  /**
   * a method that helps to get a string that will be output for the reservations query
   * the arg passed in is a single id for a given flight which is used to get the details for that specific flight using the id
   */
  public String getFlightDetails(int flight_id) {
    try {
      String quer = "SELECT day_of_month AS day, carrier_id AS carrier, flight_num AS number, origin_city AS origin, dest_city AS dest,"
        + " actual_time AS duration, capacity, price FROM flights WHERE fid = ?";
      PreparedStatement stmt = conn.prepareStatement(quer);
      stmt.setInt(1, flight_id);
      ResultSet result = stmt.executeQuery();
      if (result.next()) {
        String info = String.format("ID: %s Day: %d Carrier: %s Number: %d Origin: %s Dest: %s Duration: %d Capacity: %d Price: %d",
           flight_id, result.getInt("day"), result.getString("carrier"), result.getInt("number"), 
           result.getString("origin"), result.getString("dest"), result.getInt("duration"), 
           result.getInt("capacity"), result.getInt("price"));
        return info;
      }
      return "";
    } catch (SQLException e) {
      return "failed";
    }
  }

  /**
   * Implements the reservations function.
   *
   * @return If no user has logged in, then return "Cannot view reservations, not
   *         logged in\n" If the user has no reservations, then return "No
   *         reservations found\n" For all other errors, return "Failed to
   *         retrieve reservations\n"
   *
   *         Otherwise return the reservations in the following format:
   *
   *         Reservation [reservation ID] paid: [true or false]:\n" [flight 1
   *         under the reservation] [flight 2 under the reservation] Reservation
   *         [reservation ID] paid: [true or false]:\n" [flight 1 under the
   *         reservation] [flight 2 under the reservation] ...
   *
   *         Each flight should be printed using the same format as in the
   *         {@code Flight} class.
   *
   * @see Flight#toString()
   */
  public String transaction_reservations() {
    try {
      if (this.user == null) {
        return "User not logged in\n";
      }
      String quer = "SELECT rid, flight_type, duration, cost, paid, flight_1_id, flight_2_id FROM reservations WHERE username = ? ORDER BY rid ASC";
      PreparedStatement stmt = conn.prepareStatement(quer);
      stmt.setString(1, this.user);
      ResultSet reservations = stmt.executeQuery();
      boolean flag = true;
      String retn = "";
      while (reservations.next()) {
        flag = false;
        String flight_2 = this.getFlightDetails(reservations.getInt("flight_2_id"));
        String flight_1 = this.getFlightDetails(reservations.getInt("flight_1_id"));
        String rtn = (reservations.getString("flight_type").equals("direct")) ?
          String.format("Reservation %d paid: %b:\n%s\n",
            reservations.getInt("rid"), reservations.getBoolean("paid"),
            this.getFlightDetails(reservations.getInt("flight_1_id"))) :
          String.format("Reservation %d paid: %b:\n%s\n",
            reservations.getInt("rid"), reservations.getBoolean("paid"),
            flight_1);
        if (reservations.getString("flight_type").equals("indirect")) {
          rtn += flight_2;
        }
        retn += rtn;
      }
      if (flag) {
        return "no reservations found for " + this.user + "\n";
      }
      return retn;
    } catch (SQLException e) {
      return "Failed to retrieve reservations\n";
    }
  }

  /**
   * Implements the cancel operation.
   *
   * @param reservationId the reservation ID to cancel
   *
   * @return If no user has logged in, then return "Cannot cancel reservations,
   *         not logged in\n" For all other errors, return "Failed to cancel
   *         reservation [reservationId]\n"
   *
   *         If successful, return "Canceled reservation [reservationId]\n"
   *
   *         Even though a reservation has been canceled, its ID should not be
   *         reused by the system.
   */
  public String transaction_cancel(int reservationId) {
    try {
      int amount = 0;
      if (this.user == null) {
        return "Unauthorized, user has to be logged in\n";
      }
      PreparedStatement stmt = conn.prepareStatement("SELECT username, cost, paid, flight_1_id, flight_2_id FROM reservations WHERE rid = ?");
      stmt.setInt(1, reservationId);
      ResultSet results = stmt.executeQuery();
      if (results.next()) {
        if (!this.user.equals(results.getString("username"))) {
          return "Failed to cancel reservation " + reservationId + " \n";
        }
        if (results.getBoolean("paid")) {
          amount = results.getInt("cost");
          conn.setAutoCommit(false);
          PreparedStatement refund = conn.prepareStatement("UPDATE users SET balance = balance + ? WHERE username = ?");
          refund.setInt(1, results.getInt("cost"));
          refund.setString(2, results.getString("username"));
          refund.executeUpdate();
          conn.commit();
          conn.setAutoCommit(true);
        }
        conn.setAutoCommit(false);
        PreparedStatement cancel = conn.prepareStatement("DELETE FROM reservations WHERE rid = ?");
        cancel.setInt(1, reservationId);
        cancel.executeUpdate();
        conn.commit();
        conn.setAutoCommit(true);
      } else {
        return "Failed to cancel reservation " + reservationId + " \n";
      }
      if (amount != 0) {
        return "Canceled reservation " + reservationId + "\n";
      }
      return "Canceled reservation " + reservationId + "\n";
    } catch (SQLException e) {
      try {
        conn.rollback();
        conn.setAutoCommit(true);
      } catch (Exception er) {}
      return "Failed to cancel reservation " + reservationId + "\n";
    }
  }

  /**
   * Example utility function that uses prepared statements
   */
  private int checkFlightCapacity(int fid) throws SQLException {
    checkFlightCapacityStatement.clearParameters();
    checkFlightCapacityStatement.setInt(1, fid);
    ResultSet results = checkFlightCapacityStatement.executeQuery();
    results.next();
    int capacity = results.getInt("capacity");
    results.close();

    return capacity;
  }

  /**
   * A class to store flight information.
   */
  class Flight {
    public int fid;
    public int dayOfMonth;
    public String carrierId;
    public String flightNum;
    public String originCity;
    public String destCity;
    public int time;
    public int capacity;
    public int price;

    @Override
    public String toString() {
      return "ID: " + fid + " Day: " + dayOfMonth + " Carrier: " + carrierId + " Number: " + flightNum + " Origin: "
          + originCity + " Dest: " + destCity + " Duration: " + time + " Capacity: " + capacity + " Price: " + price;
    }
  }
}
