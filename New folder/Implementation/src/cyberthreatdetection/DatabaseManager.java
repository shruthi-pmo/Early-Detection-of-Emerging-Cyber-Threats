
package cyberthreatdetection;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class DatabaseManager {

    private static final String URL = "jdbc:sqlite:cyberthreats.db";

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL);
    }

    public static void initializeDatabase() {

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL
                )
            """);

            // Check whether the date column exists
            boolean hasDate = false;

            try (var rs = stmt.executeQuery("PRAGMA table_info(threats)")) {
                while (rs.next()) {
                    if ("created_at".equalsIgnoreCase(rs.getString("name"))) {
                        hasDate = true;
                        break;
                    }
                }
            }

            // Safely add date column to existing database
            if (!hasDate) {
                stmt.execute("ALTER TABLE threats ADD COLUMN created_at TEXT");
            }

            // Fill missing dates
            stmt.executeUpdate("""
                UPDATE threats
                SET created_at = CURRENT_TIMESTAMP
                WHERE created_at IS NULL OR created_at = ''
            """);

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS cisa_vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE NOT NULL,
                    vendor TEXT,
                    product TEXT,
                    vulnerability_name TEXT,
                    date_added TEXT,
                    due_date TEXT,
                    ransomware_use TEXT
                )
            """);

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS security_signals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signal_name TEXT NOT NULL,
                    signal_value INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    recorded_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """);

            System.out.println("Database initialized successfully!");

        } catch (SQLException e) {
            System.out.println("Database error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
