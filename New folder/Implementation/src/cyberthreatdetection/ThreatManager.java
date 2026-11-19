
package cyberthreatdetection;

import java.sql.*;
import java.util.*;

public class ThreatManager {

    public ThreatManager() {
        DatabaseManager.initializeDatabase();
    }

    public void addThreat(String name, String category, String severity) {
        String sql = "INSERT INTO threats (name, category, severity) VALUES (?, ?, ?)";

        try (Connection c = DatabaseManager.getConnection();
             PreparedStatement p = c.prepareStatement(sql)) {

            p.setString(1, name);
            p.setString(2, category);
            p.setString(3, severity);
            p.executeUpdate();

        } catch (SQLException e) {
            System.out.println("Add error: " + e.getMessage());
        }
    }

    public boolean deleteThreat(int id) {
        String sql = "DELETE FROM threats WHERE id = ?";

        try (Connection c = DatabaseManager.getConnection();
             PreparedStatement p = c.prepareStatement(sql)) {

            p.setInt(1, id);
            return p.executeUpdate() > 0;

        } catch (SQLException e) {
            System.out.println("Delete error: " + e.getMessage());
            return false;
        }
    }

    public List<Threat> getThreats() {
        List<Threat> list = new ArrayList<>();

        String sql = "SELECT id, name, category, severity, created_at FROM threats ORDER BY id";

        try (Connection c = DatabaseManager.getConnection();
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery(sql)) {

            while (r.next()) {
                list.add(new Threat(
                        r.getInt("id"),
                        r.getString("name"),
                        r.getString("category"),
                        r.getString("severity"),
                        r.getString("created_at")
                ));
            }

        } catch (SQLException e) {
            System.out.println("Read error: " + e.getMessage());
        }

        return list;
    }

    public int getTotalThreats() {
        return getThreats().size();
    }

    public int countBySeverity(String severity) {
        int count = 0;

        for (Threat t : getThreats()) {
            if (t.getSeverity().equalsIgnoreCase(severity)) {
                count++;
            }
        }

        return count;
    }

    public void saveCisaRecord(String cve, String vendor, String product,
            String vulnerability, String dateAdded, String dueDate,
            String ransomware) {

        String sql = """
            INSERT OR REPLACE INTO cisa_vulnerabilities
            (cve_id, vendor, product, vulnerability_name,
             date_added, due_date, ransomware_use)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """;

        try (Connection c = DatabaseManager.getConnection();
             PreparedStatement p = c.prepareStatement(sql)) {

            p.setString(1, cve);
            p.setString(2, vendor);
            p.setString(3, product);
            p.setString(4, vulnerability);
            p.setString(5, dateAdded);
            p.setString(6, dueDate);
            p.setString(7, ransomware);
            p.executeUpdate();

        } catch (SQLException e) {
            System.out.println("CISA import error: " + e.getMessage());
        }
    }

    public List<String[]> getCisaRecords() {
        List<String[]> records = new ArrayList<>();

        String sql = """
            SELECT cve_id, vendor, product, vulnerability_name,
                   date_added, due_date, ransomware_use
            FROM cisa_vulnerabilities ORDER BY date_added DESC
            """;

        try (Connection c = DatabaseManager.getConnection();
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery(sql)) {

            while (r.next()) {
                records.add(new String[]{
                    r.getString("cve_id"),
                    r.getString("vendor"),
                    r.getString("product"),
                    r.getString("vulnerability_name"),
                    r.getString("date_added"),
                    r.getString("due_date"),
                    r.getString("ransomware_use")
                });
            }

        } catch (SQLException e) {
            System.out.println("CISA read error: " + e.getMessage());
        }

        return records;
    }

    public void saveSignal(String name, int value, String risk) {
        String sql = """
            INSERT INTO security_signals
            (signal_name, signal_value, risk_level)
            VALUES (?, ?, ?)
            """;

        try (Connection c = DatabaseManager.getConnection();
             PreparedStatement p = c.prepareStatement(sql)) {

            p.setString(1, name);
            p.setInt(2, value);
            p.setString(3, risk);
            p.executeUpdate();

        } catch (SQLException e) {
            System.out.println("Signal error: " + e.getMessage());
        }
    }

    public List<String[]> getSignals() {
        List<String[]> signals = new ArrayList<>();

        String sql = """
            SELECT signal_name, signal_value, risk_level, recorded_at
            FROM security_signals ORDER BY id DESC
            """;

        try (Connection c = DatabaseManager.getConnection();
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery(sql)) {

            while (r.next()) {
                signals.add(new String[]{
                    r.getString("signal_name"),
                    String.valueOf(r.getInt("signal_value")),
                    r.getString("risk_level"),
                    r.getString("recorded_at")
                });
            }

        } catch (SQLException e) {
            System.out.println("Signal read error: " + e.getMessage());
        }

        return signals;
    }

    public Map<String, Integer> getMonthlyThreatCounts() {
        Map<String, Integer> result = new LinkedHashMap<>();

        String sql = """
            SELECT substr(created_at, 1, 7) AS month, COUNT(*) AS total
            FROM threats
            GROUP BY substr(created_at, 1, 7)
            ORDER BY month
            """;

        try (Connection c = DatabaseManager.getConnection();
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery(sql)) {

            while (r.next()) {
                result.put(r.getString("month"), r.getInt("total"));
            }

        } catch (SQLException e) {
            System.out.println("Monthly analysis error: " + e.getMessage());
        }

        return result;
    }

    public Map<String, Integer> getCategoryCounts() {
        Map<String, Integer> result = new LinkedHashMap<>();

        String sql = """
            SELECT category, COUNT(*) AS total
            FROM threats GROUP BY category ORDER BY total DESC
            """;

        try (Connection c = DatabaseManager.getConnection();
             Statement s = c.createStatement();
             ResultSet r = s.executeQuery(sql)) {

            while (r.next()) {
                result.put(r.getString("category"), r.getInt("total"));
            }

        } catch (SQLException e) {
            System.out.println("Category analysis error: " + e.getMessage());
        }

        return result;
    }
}
