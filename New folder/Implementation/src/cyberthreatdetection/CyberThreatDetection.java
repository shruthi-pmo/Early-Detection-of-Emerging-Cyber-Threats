
package cyberthreatdetection;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.util.*;
import java.util.List;

public class CyberThreatDetection extends JFrame {

    private final ThreatManager manager = new ThreatManager();
    private final DetectionEngine engine = new DetectionEngine();

    private DefaultTableModel tableModel;
    private JTable threatTable;

    private JLabel totalLabel;
    private JLabel highLabel;
    private JLabel criticalLabel;

    public CyberThreatDetection() {
        setTitle("Early Detection of Emerging Cyber Threats");
        setSize(1250, 750);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        createDashboard();
        refreshTable();
    }

    private void createDashboard() {
        setLayout(new BorderLayout(10, 10));

        JLabel heading = new JLabel(
                "EARLY DETECTION OF EMERGING CYBER THREATS",
                SwingConstants.CENTER);

        heading.setFont(new Font("Arial", Font.BOLD, 23));
        heading.setForeground(new Color(30, 60, 100));
        heading.setBorder(BorderFactory.createEmptyBorder(18, 10, 18, 10));

        add(heading, BorderLayout.NORTH);

        String[] columns = {
            "ID", "Threat Name", "Category", "Severity", "Date"
        };

        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        threatTable = new JTable(tableModel);
        threatTable.setRowHeight(27);
        add(new JScrollPane(threatTable), BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout());

        JPanel stats = new JPanel(new FlowLayout());
        totalLabel = new JLabel();
        highLabel = new JLabel();
        criticalLabel = new JLabel();

        stats.add(totalLabel);
        stats.add(highLabel);
        stats.add(criticalLabel);

        JPanel buttons = new JPanel(new GridLayout(3, 4, 8, 8));

        addButton(buttons, "Add Threat", this::addThreat);
        addButton(buttons, "Delete Threat", this::deleteThreat);
        addButton(buttons, "Analyze Threats", this::analyzeThreats);
        addButton(buttons, "Run Detection", this::runDetection);

        addButton(buttons, "Early Warning System", this::earlyWarning);
        addButton(buttons, "CISA Data Importer", this::importCisa);
        addButton(buttons, "View CISA Vulnerabilities", this::viewCisa);
        addButton(buttons, "Forecasting Model Comparison", this::forecastComparison);

        addButton(buttons, "Walk-Forward Validation", this::walkForward);
        addButton(buttons, "Emerging Threat Identification", this::identifyEmerging);
        addButton(buttons, "Emerging Signal Evaluation", this::evaluateSignals);
        addButton(buttons, "Refresh Dashboard", this::refreshTable);

        bottom.add(stats, BorderLayout.NORTH);
        bottom.add(buttons, BorderLayout.CENTER);

        add(bottom, BorderLayout.SOUTH);
    }

    private void addButton(JPanel panel, String text, Runnable action) {
        JButton button = new JButton(text);
        button.addActionListener(e -> action.run());
        panel.add(button);
    }

    private void refreshTable() {
        tableModel.setRowCount(0);

        for (Threat t : manager.getThreats()) {
            tableModel.addRow(new Object[]{
                t.getId(), t.getName(), t.getCategory(),
                t.getSeverity(), t.getDate()
            });
        }

        totalLabel.setText("Total Threats: " + manager.getTotalThreats());
        highLabel.setText("High: " + manager.countBySeverity("High"));
        criticalLabel.setText("Critical: " + manager.countBySeverity("Critical"));
    }

    private void addThreat() {
        JTextField name = new JTextField();
        JTextField category = new JTextField();
        JComboBox<String> severity = new JComboBox<>(
                new String[]{"Low", "Medium", "High", "Critical"});

        Object[] fields = {
            "Threat Name:", name,
            "Category:", category,
            "Severity:", severity
        };

        int result = JOptionPane.showConfirmDialog(
                this, fields, "Add Threat", JOptionPane.OK_CANCEL_OPTION);

        if (result == JOptionPane.OK_OPTION) {
            if (name.getText().trim().isEmpty()
                    || category.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "Fill in all fields.");
                return;
            }

            manager.addThreat(name.getText().trim(),
                    category.getText().trim(),
                    severity.getSelectedItem().toString());

            refreshTable();
            JOptionPane.showMessageDialog(this, "Threat added successfully.");
        }
    }

    private void deleteThreat() {
        int row = threatTable.getSelectedRow();

        if (row == -1) {
            JOptionPane.showMessageDialog(this, "Select a threat first.");
            return;
        }

        int id = Integer.parseInt(tableModel.getValueAt(row, 0).toString());

        if (manager.deleteThreat(id)) {
            refreshTable();
            JOptionPane.showMessageDialog(this, "Threat deleted.");
        }
    }

    private void analyzeThreats() {
        String message = "THREAT ANALYSIS RESULTS\n\n"
                + "Total threats: " + manager.getTotalThreats() + "\n"
                + "High-risk threats: " + manager.countBySeverity("High") + "\n"
                + "Critical threats: " + manager.countBySeverity("Critical") + "\n"
                + "Medium threats: " + manager.countBySeverity("Medium") + "\n"
                + "Low threats: " + manager.countBySeverity("Low");

        JOptionPane.showMessageDialog(this, message, "Threat Analysis",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void runDetection() {
        JTextField login = new JTextField("0");
        JTextField network = new JTextField("0");
        JTextField files = new JTextField("0");

        Object[] fields = {
            "Failed login attempts:", login,
            "Network connections:", network,
            "File modifications:", files
        };

        int result = JOptionPane.showConfirmDialog(
                this, fields, "Security Activity Analysis",
                JOptionPane.OK_CANCEL_OPTION);

        if (result != JOptionPane.OK_OPTION) return;

        try {
            int l = Integer.parseInt(login.getText().trim());
            int n = Integer.parseInt(network.getText().trim());
            int f = Integer.parseInt(files.getText().trim());

            if (l < 0 || n < 0 || f < 0) {
                JOptionPane.showMessageDialog(this, "Values cannot be negative.");
                return;
            }

            int previous = manager.getTotalThreats();

            engine.analyzeActivity(manager, l, n, f);

            refreshTable();

            int detected = manager.getTotalThreats() - previous;

            JOptionPane.showMessageDialog(this,
                    detected + " suspicious activities detected.");
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this,
                    "Enter valid whole numbers.");
        }
    }

    // MODULE 1: Analyze Threats
    // Existing analysis is available through the Analyze Threats button.

    // MODULE 2: Early Warning System
    private void earlyWarning() {
        int high = manager.countBySeverity("High");
        int critical = manager.countBySeverity("Critical");

        String warning;

        if (critical > 0) {
            warning = "CRITICAL WARNING: " + critical
                    + " critical threats require immediate attention.";
        } else if (high > 0) {
            warning = "HIGH RISK WARNING: " + high
                    + " high-severity threats detected.";
        } else {
            warning = "No high or critical threats currently recorded.";
        }

        JOptionPane.showMessageDialog(this, warning,
                "Early Warning System", JOptionPane.WARNING_MESSAGE);
    }

    // MODULE 3: CISA Data Importer
    private void importCisa() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select CISA KEV CSV File");

        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        int imported = 0;

        try (BufferedReader reader = new BufferedReader(
                new FileReader(chooser.getSelectedFile()))) {

            String headerLine = reader.readLine();

            if (headerLine == null) {
                JOptionPane.showMessageDialog(this, "The CSV file is empty.");
                return;
            }

            List<String> headers = parseCsvLine(headerLine);

            int cveIndex = findColumn(headers, "cveid");
            int vendorIndex = findColumn(headers, "vendorproject");
            int productIndex = findColumn(headers, "product");
            int nameIndex = findColumn(headers, "vulnerabilityname");
            int dateIndex = findColumn(headers, "dateadded");
            int dueIndex = findColumn(headers, "duedate");
            int ransomwareIndex = findColumn(headers,
                    "knownransomwarecampaignuse");

            if (cveIndex == -1) {
                JOptionPane.showMessageDialog(this,
                        "CVE ID column was not found. Please use the CISA KEV CSV.");
                return;
            }

            String line;

            while ((line = reader.readLine()) != null) {
                List<String> row = parseCsvLine(line);

                String cve = getValue(row, cveIndex);

                if (cve.isEmpty()) continue;

                manager.saveCisaRecord(
                        cve,
                        getValue(row, vendorIndex),
                        getValue(row, productIndex),
                        getValue(row, nameIndex),
                        getValue(row, dateIndex),
                        getValue(row, dueIndex),
                        getValue(row, ransomwareIndex)
                );

                imported++;
            }

            JOptionPane.showMessageDialog(this,
                    imported + " CISA records processed.\n"
                    + "Existing CVE IDs are updated rather than duplicated.");

        } catch (IOException e) {
            JOptionPane.showMessageDialog(this,
                    "Import error: " + e.getMessage());
        }
    }

    private List<String> parseCsvLine(String line) {
        List<String> values = new ArrayList<>();
        StringBuilder value = new StringBuilder();
        boolean quoted = false;

        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);

            if (ch == '"') {
                if (quoted && i + 1 < line.length()
                        && line.charAt(i + 1) == '"') {
                    value.append('"');
                    i++;
                } else {
                    quoted = !quoted;
                }
            } else if (ch == ',' && !quoted) {
                values.add(value.toString());
                value.setLength(0);
            } else {
                value.append(ch);
            }
        }

        values.add(value.toString());
        return values;
    }

    private int findColumn(List<String> headers, String wanted) {
        for (int i = 0; i < headers.size(); i++) {
            String normalized = headers.get(i)
                    .replace("\uFEFF", "")
                    .replaceAll("[^A-Za-z0-9]", "")
                    .toLowerCase();

            if (normalized.equals(wanted.toLowerCase())) return i;
        }

        return -1;
    }

    private String getValue(List<String> row, int index) {
        if (index < 0 || index >= row.size()) return "";
        return row.get(index).trim();
    }

    // MODULE 4: View CISA Vulnerabilities
    private void viewCisa() {
        String[] columns = {
            "CVE ID", "Vendor", "Product", "Vulnerability",
            "Date Added", "Due Date", "Ransomware Use"
        };

        DefaultTableModel model = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };

        for (String[] record : manager.getCisaRecords()) {
            model.addRow(record);
        }

        JTable table = new JTable(model);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setRowHeight(24);

        JScrollPane scroll = new JScrollPane(table);
        scroll.setPreferredSize(new Dimension(1050, 400));

        JOptionPane.showMessageDialog(this, scroll,
                "CISA Known Exploited Vulnerabilities",
                JOptionPane.INFORMATION_MESSAGE);
    }

    // MODULE 5: Forecasting Model Comparison
    private void forecastComparison() {
        List<Integer> values = new ArrayList<>(
                manager.getMonthlyThreatCounts().values());

        if (values.size() < 2) {
            JOptionPane.showMessageDialog(this,
                    "At least two different months of threat records are needed.");
            return;
        }

        double lastMonth = values.get(values.size() - 1);

        double movingAverage = 0;
        int start = Math.max(0, values.size() - 3);

        for (int i = start; i < values.size(); i++) {
            movingAverage += values.get(i);
        }

        movingAverage /= values.size() - start;

        String message = "FORECASTING MODEL COMPARISON\n\n"
                + "Latest month threat count: " + (int) lastMonth + "\n"
                + "Baseline forecast (last month): " + lastMonth + "\n"
                + "Moving average forecast: "
                + String.format("%.2f", movingAverage)
                + "\n\nThese are simple statistical baselines, not trained AI models.";

        JOptionPane.showMessageDialog(this, message,
                "Forecasting Model Comparison",
                JOptionPane.INFORMATION_MESSAGE);
    }

    // MODULE 6: Walk-Forward Validation
    private void walkForward() {
        List<Integer> values = new ArrayList<>(
                manager.getMonthlyThreatCounts().values());

        if (values.size() < 3) {
            JOptionPane.showMessageDialog(this,
                    "At least three months of records are needed for validation.");
            return;
        }

        double baselineError = 0;
        double averageError = 0;
        int tests = 0;

        for (int i = 1; i < values.size(); i++) {
            double actual = values.get(i);
            double baselinePrediction = values.get(i - 1);

            baselineError += Math.abs(actual - baselinePrediction);

            double sum = 0;

            for (int j = 0; j < i; j++) {
                sum += values.get(j);
            }

            double averagePrediction = sum / i;
            averageError += Math.abs(actual - averagePrediction);

            tests++;
        }

        String message = "WALK-FORWARD VALIDATION RESULTS\n\n"
                + "Validation periods: " + tests + "\n"
                + "Baseline MAE: " + String.format("%.2f",
                        baselineError / tests) + "\n"
                + "Average model MAE: " + String.format("%.2f",
                        averageError / tests) + "\n\n"
                + "Lower MAE indicates better prediction accuracy.";

        JOptionPane.showMessageDialog(this, message,
                "Walk-Forward Validation",
                JOptionPane.INFORMATION_MESSAGE);
    }

    // MODULE 7: Emerging Threat Identification
    private void identifyEmerging() {
        Map<String, Integer> categories = manager.getCategoryCounts();

        if (categories.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "No threat records available.");
            return;
        }

        StringBuilder result = new StringBuilder(
                "THREAT CATEGORY FREQUENCY ANALYSIS\n\n");

        for (Map.Entry<String, Integer> entry : categories.entrySet()) {
            result.append(entry.getKey())
                    .append(" : ")
                    .append(entry.getValue())
                    .append(" records\n");
        }

        result.append("\nCategories with higher counts appear more frequently.")
                .append("\nThis is frequency analysis, not proof of a new threat.");

        JOptionPane.showMessageDialog(this, result.toString(),
                "Emerging Threat Identification",
                JOptionPane.INFORMATION_MESSAGE);
    }

    // MODULE 8: Emerging Signal Evaluation
    private void evaluateSignals() {
        JTextField name = new JTextField();
        JTextField value = new JTextField();

        Object[] fields = {
            "Signal Name:", name,
            "Signal Value (number):", value
        };

        int choice = JOptionPane.showConfirmDialog(this, fields,
                "Evaluate Emerging Signal", JOptionPane.OK_CANCEL_OPTION);

        if (choice != JOptionPane.OK_OPTION) return;

        try {
            String signalName = name.getText().trim();
            int signalValue = Integer.parseInt(value.getText().trim());

            if (signalName.isEmpty() || signalValue < 0) {
                JOptionPane.showMessageDialog(this,
                        "Enter a signal name and a non-negative value.");
                return;
            }

            String risk = engine.evaluateSignal(signalValue);

            manager.saveSignal(signalName, signalValue, risk);

            JOptionPane.showMessageDialog(this,
                    "SIGNAL EVALUATION RESULT\n\n"
                    + "Signal: " + signalName + "\n"
                    + "Value: " + signalValue + "\n"
                    + "Risk Level: " + risk,
                    "Signal Evaluation",
                    JOptionPane.INFORMATION_MESSAGE);

        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this,
                    "Signal value must be a whole number.");
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new CyberThreatDetection().setVisible(true);
        });
    }
}

