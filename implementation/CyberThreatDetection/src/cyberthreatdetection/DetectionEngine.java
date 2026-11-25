
package cyberthreatdetection;

public class DetectionEngine {

    public void analyzeActivity(
            ThreatManager manager,
            int failedLogins,
            int networkConnections,
            int fileChanges) {

        // Rule 1: Detect repeated failed login attempts
        if (failedLogins >= 5) {
            manager.addThreat(
                    "Multiple Failed Login Attempts",
                    "Unauthorized Access",
                    "High"
            );
        }

        // Rule 2: Detect unusually high network connections
        if (networkConnections >= 100) {
            manager.addThreat(
                    "Unusual Network Connection Activity",
                    "Network Attack",
                    "Critical"
            );
        }

        // Rule 3: Detect excessive file modifications
        if (fileChanges >= 20) {
            manager.addThreat(
                    "Suspicious File Modifications",
                    "Possible Malware Activity",
                    "High"
            );
        }
    }
}
