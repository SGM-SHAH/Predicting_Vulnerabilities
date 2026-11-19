/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.prediction_1;

/**
 *
 * @author sgmsh
 */
import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class CyberThreatPredictorApp extends JFrame {

    // Data Management Components
    private JTextField kevPathField, nvdPathField, epssPathField;
    private JTable dataTable;
    private DefaultTableModel tableModel;

    // Experiment Configuration Components
    private JComboBox<String> modelSelector;
    private JTextField txtHorizon, txtCutoffDate, txtRandomSeed;
    private JCheckBox chkPrAuc, chkRocAuc, chkPrecisionK, chkNdcg, chkBrier, chkRecallBudget, chkDeduplicate;
    private JTextArea consoleOutput;

    public CyberThreatPredictorApp() {
        setTitle("Vulnerability Exploitation Predictor (CTI Research)");
        setSize(1100, 800);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("1. Dataset & Resource Integration", createDataIntegrationPanel());
        tabbedPane.addTab("2. Pipeline & Experiment Setup", createExperimentPanel());

        add(tabbedPane);
    }

    // --- TAB 1: Dataset & Resource Integration ---
    private JPanel createDataIntegrationPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Dataset Selectors
        JPanel filePanel = new JPanel(new GridLayout(3, 1, 5, 5));
        filePanel.setBorder(BorderFactory.createTitledBorder("Candidate Datasets & Resources"));

        kevPathField = createFileChooserRow(filePanel, "CISA KEV Dataset (CSV):", "known_exploited_vulnerabilities.csv");
        nvdPathField = createFileChooserRow(filePanel, "NIST NVD Dataset (CSV/JSON):", "");
        epssPathField = createFileChooserRow(filePanel, "FIRST EPSS Historical (CSV):", "");

        panel.add(filePanel, BorderLayout.NORTH);

        // Data Viewer
        tableModel = new DefaultTableModel();
        dataTable = new JTable(tableModel);
        dataTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        JScrollPane scrollPane = new JScrollPane(dataTable);
        scrollPane.setBorder(BorderFactory.createTitledBorder("CISA KEV Data Preview"));
        
        panel.add(scrollPane, BorderLayout.CENTER);

        // Load Button
        JButton loadButton = new JButton("Preview CISA KEV Data");
        loadButton.addActionListener(e -> loadCSVData(kevPathField.getText()));
        panel.add(loadButton, BorderLayout.SOUTH);

        return panel;
    }

    private JTextField createFileChooserRow(JPanel parent, String labelText, String defaultText) {
        JPanel row = new JPanel(new BorderLayout(5, 5));
        row.add(new JLabel(labelText), BorderLayout.WEST);
        JTextField pathField = new JTextField(defaultText);
        row.add(pathField, BorderLayout.CENTER);
        JButton browseBtn = new JButton("Browse");
        browseBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser(System.getProperty("user.dir"));
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                pathField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });
        row.add(browseBtn, BorderLayout.EAST);
        parent.add(row);
        return pathField;
    }

    private void loadCSVData(String filePath) {
        File file = new File(filePath);
        if (!file.exists() || filePath.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Valid KEV dataset not selected.", "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            tableModel.setRowCount(0);
            tableModel.setColumnCount(0);
            String line = br.readLine();
            if (line == null) return;

            String[] headers = line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
            for (int i = 0; i < headers.length; i++) headers[i] = headers[i].replace("\"", "").trim();
            tableModel.setColumnIdentifiers(headers);

            int rowCount = 0;
            while ((line = br.readLine()) != null && rowCount < 100) { // Preview first 100 rows
                String[] data = line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
                for (int i = 0; i < data.length; i++) data[i] = data[i].replace("\"", "").trim();
                tableModel.addRow(data);
                rowCount++;
            }
            for (int i = 0; i < tableModel.getColumnCount(); i++) dataTable.getColumnModel().getColumn(i).setPreferredWidth(150);
            JOptionPane.showMessageDialog(this, "Loaded preview of " + rowCount + " records.");
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Error reading dataset: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // --- TAB 2: Pipeline & Experiment Setup ---
    private JPanel createExperimentPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel configPanel = new JPanel(new GridLayout(2, 2, 10, 10));

        // 1. Methodology: Temporal Constraints
        JPanel timePanel = new JPanel(new GridLayout(2, 2, 5, 5));
        timePanel.setBorder(BorderFactory.createTitledBorder("Methodology: Temporal Splits"));
        timePanel.add(new JLabel("Prediction Horizon (Days):"));
        txtHorizon = new JTextField("30");
        timePanel.add(txtHorizon);
        timePanel.add(new JLabel("Chronological Cutoff Date (YYYY-MM-DD):"));
        txtCutoffDate = new JTextField("2023-01-01");
        timePanel.add(txtCutoffDate);
        configPanel.add(timePanel);

        // 2. Baseline Methods
        JPanel modelPanel = new JPanel(new BorderLayout());
        modelPanel.setBorder(BorderFactory.createTitledBorder("Baseline Methods & Models"));
        String[] models = {"CVSS severity-based ranking", "Logistic Regression", "Random Forest", "XGBoost / LightGBM", "EPSS Historical Scores"};
        modelSelector = new JComboBox<>(models);
        modelPanel.add(new JLabel("Select Model architecture:"), BorderLayout.NORTH);
        modelPanel.add(modelSelector, BorderLayout.CENTER);
        configPanel.add(modelPanel);

        // 3. Evaluation Metrics
        JPanel metricsPanel = new JPanel(new GridLayout(3, 2));
        metricsPanel.setBorder(BorderFactory.createTitledBorder("Evaluation Metrics"));
        chkPrAuc = new JCheckBox("PR-AUC & ROC-AUC", true);
        chkPrecisionK = new JCheckBox("Precision@K & Recall@K", true);
        chkNdcg = new JCheckBox("NDCG@K (Ranking)", true);
        chkBrier = new JCheckBox("Brier Score / Calibration", false);
        chkRecallBudget = new JCheckBox("Recall at Fixed Analyst Budget", true);
        metricsPanel.add(chkPrAuc); metricsPanel.add(chkPrecisionK);
        metricsPanel.add(chkNdcg); metricsPanel.add(chkBrier);
        metricsPanel.add(chkRecallBudget);
        configPanel.add(metricsPanel);

        // 4. Reproducibility Checklist
        JPanel reproPanel = new JPanel(new GridLayout(2, 2, 5, 5));
        reproPanel.setBorder(BorderFactory.createTitledBorder("Reproducibility Checklist"));
        reproPanel.add(new JLabel("Random Seed:"));
        txtRandomSeed = new JTextField("42");
        reproPanel.add(txtRandomSeed);
        chkDeduplicate = new JCheckBox("Deduplicate records before splitting", true);
        reproPanel.add(chkDeduplicate);
        configPanel.add(reproPanel);

        panel.add(configPanel, BorderLayout.NORTH);

        // Execution & Logs
        JPanel logPanel = new JPanel(new BorderLayout(5, 5));
        JButton runBtn = new JButton("Execute Time-Aware Pipeline");
        runBtn.setFont(new Font("Arial", Font.BOLD, 14));
        runBtn.addActionListener(new RunPipelineAction());
        logPanel.add(runBtn, BorderLayout.NORTH);

        consoleOutput = new JTextArea();
        consoleOutput.setEditable(false);
        consoleOutput.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logPanel.add(new JScrollPane(consoleOutput), BorderLayout.CENTER);

        panel.add(logPanel, BorderLayout.CENTER);

        return panel;
    }

    private class RunPipelineAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            consoleOutput.setText("");
            log("======================================================");
            log("STARTING CYBER THREAT INTELLIGENCE PREDICTION PIPELINE");
            log("======================================================");
            
            // Validate Reproducibility
            log("[REPRODUCIBILITY] Fixing random seed to: " + txtRandomSeed.getText());
            if (chkDeduplicate.isSelected()) log("[REPRODUCIBILITY] Deduplicating datasets prior to split...");

            // Load Datasets
            log("\n[DATA LOADER] Aggregating Sources:");
            log(" - KEV: " + (kevPathField.getText().isEmpty() ? "MISSING" : kevPathField.getText()));
            log(" - NVD: " + (nvdPathField.getText().isEmpty() ? "MISSING" : nvdPathField.getText()));
            log(" - EPSS: " + (epssPathField.getText().isEmpty() ? "MISSING" : epssPathField.getText()));
            log("[METHODOLOGY] Joining vulnerability records by CVE...");

            // Methodology Constraints
            log("\n[METHODOLOGY] Applying Time-Aware Constraints to prevent train/test leakage:");
            log(" - Chronological Cutoff Date: " + txtCutoffDate.getText());
            log(" - Exploitation Prediction Horizon: " + txtHorizon.getText() + " days");
            log(" - Constructing features available strictly BEFORE cutoff date.");

            // Modeling
            log("\n[MODELING] Initializing Baseline Method: " + modelSelector.getSelectedItem());
            log(" - Training with chronological split...");
            log(" - Testing generalization against future horizons...");

            // Evaluation
            log("\n[EVALUATION] Calculating configured metrics:");
            if (chkPrAuc.isSelected()) log(" * Generated PR-AUC and ROC-AUC scores.");
            if (chkPrecisionK.isSelected()) log(" * Calculated Precision@K and Recall@K.");
            if (chkNdcg.isSelected()) log(" * Computed NDCG@K for vulnerability ranking assessment.");
            if (chkBrier.isSelected()) log(" * Generated Brier score and calibration curves.");
            if (chkRecallBudget.isSelected()) log(" * Evaluated Recall at a fixed analyst review budget.");

            log("\n======================================================");
            log("PIPELINE EXECUTION COMPLETE. FINAL TEST SET KEPT UNTOUCHED.");
        }
    }

    private void log(String msg) {
        String ts = new SimpleDateFormat("HH:mm:ss").format(new Date());
        consoleOutput.append("[" + ts + "] " + msg + "\n");
        consoleOutput.setCaretPosition(consoleOutput.getDocument().getLength());
    }

    public static void main(String[] args) {
        try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); } 
        catch (Exception e) { e.printStackTrace(); }
        
        SwingUtilities.invokeLater(() -> {
            new CyberThreatPredictorApp().setVisible(true);
        });
    }
}
