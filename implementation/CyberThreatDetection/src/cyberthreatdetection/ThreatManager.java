
package cyberthreatdetection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class ThreatManager {

    public ThreatManager() {
        DatabaseManager.initializeDatabase();
    }

    public void addThreat(String name, String category, String severity) {
        String sql = "INSERT INTO threats (name, category, severity) VALUES (?, ?, ?)";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, name);
            pstmt.setString(2, category);
            pstmt.setString(3, severity);
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.out.println("Error adding threat: " + e.getMessage());
        }
    }

    public boolean deleteThreat(int id) {
        String sql = "DELETE FROM threats WHERE id = ?";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, id);
            return pstmt.executeUpdate() > 0;

        } catch (SQLException e) {
            System.out.println("Error deleting threat: " + e.getMessage());
            return false;
        }
    }

    public List<Threat> getThreats() {
        List<Threat> threats = new ArrayList<>();

        String sql = "SELECT * FROM threats ORDER BY id";

        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            while (rs.next()) {
                Threat threat = new Threat(
                    rs.getInt("id"),
                    rs.getString("name"),
                    rs.getString("category"),
                    rs.getString("severity")
                );

                threats.add(threat);
            }

        } catch (SQLException e) {
            System.out.println("Error retrieving threats: " + e.getMessage());
        }

        return threats;
    }

    public int getTotalThreats() {
        return getThreats().size();
    }

    public int countBySeverity(String severity) {
        int count = 0;

        for (Threat threat : getThreats()) {
            if (threat.getSeverity().equalsIgnoreCase(severity)) {
                count++;
            }
        }

        return count;
    }
}
