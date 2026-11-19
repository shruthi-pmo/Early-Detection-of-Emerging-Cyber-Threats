
package cyberthreatdetection;

public class DetectionEngine {

    public void analyzeActivity(ThreatManager manager,
            int failedLogins, int networkConnections, int fileChanges) {

        if (failedLogins >= 5) {
            manager.addThreat(
                    "Multiple Failed Login Attempts",
                    "Unauthorized Access",
                    failedLogins >= 10 ? "Critical" : "High"
            );
        }

        if (networkConnections >= 100) {
            manager.addThreat(
                    "Unusual Network Activity",
                    "Network Attack",
                    networkConnections >= 200 ? "Critical" : "High"
            );
        }

        if (fileChanges >= 20) {
            manager.addThreat(
                    "Unusual File Modifications",
                    "Suspicious File Activity",
                    fileChanges >= 50 ? "Critical" : "High"
            );
        }
    }

    public String evaluateSignal(int value) {
        if (value >= 100) {
            return "Critical";
        } else if (value >= 50) {
            return "High";
        } else if (value >= 20) {
            return "Medium";
        }

        return "Low";
    }
}

