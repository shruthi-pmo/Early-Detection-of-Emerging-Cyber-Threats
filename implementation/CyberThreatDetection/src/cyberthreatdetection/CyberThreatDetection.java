
package cyberthreatdetection;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

public class CyberThreatDetection extends JFrame {

    private final ThreatManager manager = new ThreatManager();
    private final DetectionEngine detectionEngine = new DetectionEngine();

    private DefaultTableModel tableModel;
    private JTable threatTable;

    private JLabel totalLabel;
    private JLabel highLabel;
    private JLabel criticalLabel;

    public CyberThreatDetection() {
        setTitle("Cyber Threat Detection System");
        setSize(1050, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        createDashboard();
        refreshTable();
    }

    private void createDashboard() {
        setLayout(new BorderLayout(10, 10));

        JLabel heading = new JLabel(
                "CYBER THREAT DETECTION SYSTEM",
                SwingConstants.CENTER
        );

        heading.setFont(new Font("Arial", Font.BOLD, 24));
        heading.setForeground(new Color(30, 60, 100));
        heading.setBorder(
                BorderFactory.createEmptyBorder(20, 10, 20, 10)
        );

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
        threatTable.setRowHeight(28);

        add(new JScrollPane(threatTable), BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout());

        JPanel statistics = new JPanel(
                new FlowLayout(FlowLayout.CENTER, 30, 10)
        );

        totalLabel = new JLabel();
        highLabel = new JLabel();
        criticalLabel = new JLabel();

        statistics.add(totalLabel);
        statistics.add(highLabel);
        statistics.add(criticalLabel);

        JPanel buttons = new JPanel(new FlowLayout());

        JButton addButton = new JButton("Add Threat");
        JButton deleteButton = new JButton("Delete Threat");
        JButton analyzeButton = new JButton("Analyze Threats");
        JButton detectButton = new JButton("Run Detection");

        buttons.add(addButton);
        buttons.add(deleteButton);
        buttons.add(analyzeButton);
        buttons.add(detectButton);

        bottomPanel.add(statistics, BorderLayout.NORTH);
        bottomPanel.add(buttons, BorderLayout.SOUTH);

        add(bottomPanel, BorderLayout.SOUTH);

        addButton.addActionListener(e -> addThreat());
        deleteButton.addActionListener(e -> deleteThreat());
        analyzeButton.addActionListener(e -> analyzeThreats());
        detectButton.addActionListener(e -> runDetection());
    }

    private void addThreat() {
        JTextField nameField = new JTextField();
        JTextField categoryField = new JTextField();

        String[] levels = {"Low", "Medium", "High", "Critical"};
        JComboBox<String> severityBox = new JComboBox<>(levels);

        Object[] fields = {
            "Threat Name:", nameField,
            "Category:", categoryField,
            "Severity:", severityBox
        };

        int result = JOptionPane.showConfirmDialog(
                this, fields, "Add New Threat",
                JOptionPane.OK_CANCEL_OPTION
        );

        if (result == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            String category = categoryField.getText().trim();
            String severity = (String) severityBox.getSelectedItem();

            if (name.isEmpty() || category.isEmpty()) {
                JOptionPane.showMessageDialog(
                        this, "Please fill in all fields."
                );
                return;
            }

            manager.addThreat(name, category, severity);
            refreshTable();

            JOptionPane.showMessageDialog(
                    this, "Threat added successfully!"
            );
        }
    }

    private void deleteThreat() {
        int selectedRow = threatTable.getSelectedRow();

        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(
                    this, "Please select a threat to delete."
            );
            return;
        }

        int id = (int) tableModel.getValueAt(selectedRow, 0);

        manager.deleteThreat(id);
        refreshTable();

        JOptionPane.showMessageDialog(
                this, "Threat deleted successfully!"
        );
    }

    private void analyzeThreats() {
        String message = "THREAT ANALYSIS RESULTS\n\n"
                + "Total threats: " + manager.getTotalThreats() + "\n"
                + "High-risk threats: " + manager.countBySeverity("High") + "\n"
                + "Critical threats: " + manager.countBySeverity("Critical");

        JOptionPane.showMessageDialog(
                this, message, "Threat Analysis",
                JOptionPane.INFORMATION_MESSAGE
        );
    }

    private void runDetection() {

        JTextField loginField = new JTextField("0");
        JTextField networkField = new JTextField("0");
        JTextField fileField = new JTextField("0");

        Object[] fields = {
            "Number of failed login attempts:", loginField,
            "Number of network connections:", networkField,
            "Number of file modifications:", fileField
        };

        int result = JOptionPane.showConfirmDialog(
                this,
                fields,
                "Security Activity Analysis",
                JOptionPane.OK_CANCEL_OPTION
        );

        if (result != JOptionPane.OK_OPTION) {
            return;
        }

        try {
            int failedLogins = Integer.parseInt(loginField.getText().trim());
            int networkConnections = Integer.parseInt(networkField.getText().trim());
            int fileChanges = Integer.parseInt(fileField.getText().trim());

            if (failedLogins < 0 || networkConnections < 0 || fileChanges < 0) {
                JOptionPane.showMessageDialog(
                        this, "Values cannot be negative."
                );
                return;
            }

            int previousCount = manager.getTotalThreats();

            detectionEngine.analyzeActivity(
                    manager,
                    failedLogins,
                    networkConnections,
                    fileChanges
            );

            refreshTable();

            int detected = manager.getTotalThreats() - previousCount;

            JOptionPane.showMessageDialog(
                    this,
                    detected + " suspicious activities detected.",
                    "Detection Results",
                    JOptionPane.INFORMATION_MESSAGE
            );

        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please enter valid whole numbers.",
                    "Invalid Input",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }

    private void refreshTable() {
        tableModel.setRowCount(0);

        for (Threat threat : manager.getThreats()) {
            tableModel.addRow(new Object[]{
                threat.getId(),
                threat.getName(),
                threat.getCategory(),
                threat.getSeverity(),
                threat.getDate()
            });
        }

        totalLabel.setText(
                "Total Threats: " + manager.getTotalThreats()
        );

        highLabel.setText(
                "High: " + manager.countBySeverity("High")
        );

        criticalLabel.setText(
                "Critical: " + manager.countBySeverity("Critical")
        );
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new CyberThreatDetection().setVisible(true);
        });
    }
}
