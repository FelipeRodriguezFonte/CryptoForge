package com.cryptoforge.ui;

import com.cryptoforge.crypto.EMVOperations;

import javafx.fxml.FXML;
import javafx.scene.control.*;

/**
 * Controller for EMV tab operations
 * Handles ARQC/ARPC, session key derivation, and EMV cryptography
 * 
 * @author Felipe
 */
public class EMVController {

    private StatusReporter mainController;

    // Session Key Derivation controls
    private TextField imkField;
    private TextField panFieldSession;
    private TextField panSeqFieldSession;
    private TextField atcField;
    private TextArea sessionKeyResultArea;

    // ARQC Generation controls
    private TextField skARQCField;
    private TextField amountField;
    private TextField currencyField;
    private TextField countryField;
    private TextField atcARQCField;
    private TextField tvrField;
    private TextField txDateField;
    private TextField txTypeField;
    private TextField unField;
    private TextArea arqcResultArea;

    // ARPC Generation controls
    private TextField skARPCField;
    private TextField arqcField;
    private TextField arcField;
    private TextField csuField;
    private ComboBox<String> arpcMethodCombo;
    private TextArea arpcResultArea;

    // Track 2 controls
    private TextField panTrack2Field;
    private TextField expiryTrack2Field;
    private TextField serviceCodeFieldTrack2;
    private TextField discretionaryDataField;
    private TextField track2InputField;
    private TextArea track2ResultArea;

    // New fields
    private TextArea arqcTerminalDataField;
    private TextField amountOtherField;
    private TextField iccDataField;
    private ComboBox<String> arqcPaddingMethodCombo;
    private TextField propAuthDataField; // New

    public void initialize(StatusReporter mainController,
            // Session Key fields
            TextField imkField,
            TextField panFieldSession,
            TextField panSeqFieldSession,
            TextField atcField,
            TextArea sessionKeyResultArea,
            // ARQC fields
            TextField skARQCField,
            TextField amountField,
            TextField currencyField,
            TextField countryField,
            TextField atcARQCField,
            TextField tvrField,
            TextField txDateField,
            TextField txTypeField,
            TextField unField,
            TextArea arqcResultArea,
            TextArea arqcTerminalDataField, // New
            TextField amountOtherField, // New
            TextField iccDataField, // New
            ComboBox<String> arqcPaddingMethodCombo, // New
            // ARQC fields (end)
            // ARPC fields
            TextField skARPCField,
            TextField arqcField,
            TextField arcField,
            TextField csuField,
            TextField propAuthDataField, // New
            ComboBox<String> arpcMethodCombo,
            TextArea arpcResultArea,
            // Track 2 fields
            TextField panTrack2Field,
            TextField expiryTrack2Field,
            TextField serviceCodeFieldTrack2,
            TextField discretionaryDataField,
            TextField track2InputField,
            TextArea track2ResultArea) {

        this.mainController = mainController;
        this.imkField = imkField;
        this.panFieldSession = panFieldSession;
        this.panSeqFieldSession = panSeqFieldSession;
        this.atcField = atcField;
        this.sessionKeyResultArea = sessionKeyResultArea;
        this.arqcPaddingMethodCombo = arqcPaddingMethodCombo;

        setupARQCPaddingMethods();

        this.skARQCField = skARQCField;
        this.amountField = amountField;
        this.currencyField = currencyField;
        this.countryField = countryField;
        this.atcARQCField = atcARQCField;
        this.tvrField = tvrField;
        this.txDateField = txDateField;
        this.txTypeField = txTypeField;
        this.unField = unField;
        this.arqcResultArea = arqcResultArea;
        this.arqcTerminalDataField = arqcTerminalDataField; // New
        this.amountOtherField = amountOtherField; // New
        this.iccDataField = iccDataField; // New

        this.skARPCField = skARPCField;
        this.arqcField = arqcField;
        this.arcField = arcField;
        this.csuField = csuField;
        this.propAuthDataField = propAuthDataField; // New
        this.arpcMethodCombo = arpcMethodCombo;
        this.arpcResultArea = arpcResultArea;

        this.panTrack2Field = panTrack2Field;
        this.expiryTrack2Field = expiryTrack2Field;
        this.serviceCodeFieldTrack2 = serviceCodeFieldTrack2;
        this.discretionaryDataField = discretionaryDataField;
        this.track2InputField = track2InputField;
        this.track2ResultArea = track2ResultArea;

        setupARPCMethods();
    }

    private void setupARPCMethods() {
        arpcMethodCombo.getItems().addAll(
                "Method 1 (XOR with ARQC)",
                "Method 2 (CSU Method)");
        arpcMethodCombo.getSelectionModel().selectFirst();
    }

    // Helper to setup padding methods
    private void setupARQCPaddingMethods() {
        if (arqcPaddingMethodCombo != null) {
            arqcPaddingMethodCombo.getItems().clear();
            arqcPaddingMethodCombo.getItems().addAll(
                    "Method 1 (ISO 9797-1)",
                    "Method 2 (ISO 9797-1 / EMV)");
            arqcPaddingMethodCombo.getSelectionModel().selectFirst(); // Defaults to Method 1
        }
    }

    // ============================================================================
    // SESSION KEY DERIVATION
    // ============================================================================

    public void handleDeriveSessionKey() {
        try {
            String imk = imkField.getText().trim().replaceAll("\\s+", "");
            String pan = panFieldSession.getText().trim().replaceAll("\\s+", "");
            String panSeq = panSeqFieldSession.getText().trim();
            String atc = atcField.getText().trim().replaceAll("\\s+", "");

            if (imk.isEmpty() || pan.isEmpty()) {
                sessionKeyResultArea.setText("Error: IMK and PAN are required");
                return;
            }

            if (panSeq.isEmpty()) {
                panSeq = "00";
            }

            StringBuilder result = new StringBuilder();
            result.append("EMV SESSION KEY DERIVATION\n");
            result.append("═══════════════════════════\n\n");

            // Step 1: Derive ICC Master Key
            result.append("Step 1: Derive ICC Master Key (UDK)\n");
            result.append("───────────────────────────────────\n");
            String iccMK = EMVOperations.deriveICCMasterKey(imk, pan, panSeq);
            result.append("IMK: ").append(imk).append("\n");
            result.append("PAN: ").append(pan).append("\n");
            result.append("PAN Sequence: ").append(panSeq).append("\n");
            result.append("➜ ICC Master Key: ").append(iccMK).append("\n\n");

            // Step 2: Derive Session Key (if ATC provided)
            if (!atc.isEmpty()) {
                result.append("Step 2: Derive Session Key\n");
                result.append("───────────────────────────\n");
                String sessionKey = EMVOperations.deriveSessionKey(iccMK, atc, "");
                result.append("ICC Master Key: ").append(iccMK).append("\n");
                result.append("ATC: ").append(atc).append(" (").append(EMVOperations.formatATC(atc)).append(")\n");
                result.append("➜ Session Key: ").append(sessionKey).append("\n\n");
            }

            result.append("✅ Session key derivation complete\n");
            sessionKeyResultArea.setText(result.toString());
            sessionKeyResultArea.setVisible(true);
            sessionKeyResultArea.setManaged(true);

            // Add to history
            java.util.Map<String, String> historyMap = new java.util.HashMap<>();
            historyMap.put("Input",
                    "IMK: " + imk.substring(0, Math.min(8, imk.length())) + "..., PAN: " + pan + ", ATC: " + atc);
            historyMap.put("Output", "Keys derived successfully");
            mainController.addToHistory("Session Key Derivation", historyMap);

        } catch (Exception e) {
            sessionKeyResultArea.setText("Error: " + e.getMessage());
            sessionKeyResultArea.setVisible(true);
            sessionKeyResultArea.setManaged(true);
        }
    }

    // ============================================================================
    // ARQC GENERATION
    // ============================================================================

    // ============================================================================
    // ARQC GENERATION
    // ============================================================================

    public void handleGenerateARQC() {
        try {
            String sk = skARQCField.getText().trim().replaceAll("\\s+", "");

            // Check for Raw Data override
            String rawData = arqcTerminalDataField != null
                    ? arqcTerminalDataField.getText().trim().replaceAll("\\s+", "")
                    : "";

            String txData;
            String amount = "";
            String amountOther = "";
            String currency = "";
            String country = "";
            String atc = "";
            String tvr = "";
            String txDate = "";
            String txType = "";
            String un = "";

            if (!rawData.isEmpty()) {
                // Use Raw Data directly
                txData = rawData;
                atc = atcARQCField.getText().trim(); // Still read for history/info
            } else {
                // Construct from Individual Fields (BP Tools Structure)
                amount = amountField.getText().trim().replaceAll("\\s+", "");
                amountOther = amountOtherField != null ? amountOtherField.getText().trim().replaceAll("\\s+", "")
                        : "";
                currency = currencyField.getText().trim().replaceAll("\\s+", "");
                country = countryField.getText().trim().replaceAll("\\s+", "");
                atc = atcARQCField.getText().trim().replaceAll("\\s+", ""); // Info/Key derivation context
                tvr = tvrField.getText().trim().replaceAll("\\s+", "");
                txDate = txDateField.getText().trim().replaceAll("\\s+", "");
                txType = txTypeField.getText().trim().replaceAll("\\s+", "");
                un = unField.getText().trim().replaceAll("\\s+", "");

                if (sk.isEmpty() || amount.isEmpty()) {
                    arqcResultArea.setText("Error: Session Key and Amount are required");
                    return;
                }

                // Set defaults if not provided
                if (amountOther.isEmpty())
                    amountOther = "000000000000";
                if (currency.isEmpty())
                    currency = "0978"; // EUR
                if (country.isEmpty())
                    country = "0724"; // Spain
                if (tvr.isEmpty())
                    tvr = "0000000000"; // All zeros
                if (txDate.isEmpty())
                    txDate = "251207"; // YYMMDD
                if (txType.isEmpty())
                    txType = "00"; // Purchase
                if (un.isEmpty())
                    un = "12345678"; // Random UN

                // Build transaction data (New Structure: Amt, AmtOther, Ctry, TVR, Cur, Date,
                // Type, UN)
                txData = EMVOperations.buildARQCData(
                        amount, amountOther, country, tvr, currency, txDate, txType, un);
            }

            // Append ICC Data if present (Applicable to BOTH Raw and Constructed modes)
            String iccData = iccDataField != null ? iccDataField.getText().trim().replaceAll("\\s+", "") : "";
            if (!iccData.isEmpty()) {
                txData += iccData;
            }

            StringBuilder result = new StringBuilder();
            result.append("ARQC GENERATION (Authorization Request Cryptogram)\n");
            result.append("═══════════════════════════════════════════════════\n\n");

            if (!rawData.isEmpty()) {
                result.append("Using Raw Terminal Data:\n").append(rawData).append("\n");
                if (!iccData.isEmpty()) {
                    result.append("Appended ICC Data:\n").append(iccData).append("\n");
                }
                result.append("Total Input for MAC:\n").append(txData).append("\n\n");
            } else {
                result.append("Transaction Data (BP-Tools Structure):\n");
                result.append("─────────────────\n");
                result.append("Amount: ").append(amount).append("\n");
                result.append("Amount Other: ")
                        .append(amountOther).append("\n");
                result.append("Country: ").append(country).append(" (Spain/ES)\n");
                result.append("TVR: ").append(tvr).append("\n");
                // ... (simplified logs)
                result.append("Concatenated Data: ").append(txData).append("\n\n");
            }

            // Generate ARQC
            result.append("ARQC Calculation:\n");
            result.append("─────────────────\n");
            result.append("Session Key: ").append(sk).append("\n");

            // Determine Padding Method
            int paddingMethod = 1; // Default
            if (arqcPaddingMethodCombo != null && arqcPaddingMethodCombo.getValue() != null) {
                if (arqcPaddingMethodCombo.getValue().contains("Method 2")) {
                    paddingMethod = 2;
                }
            }
            result.append("Padding Method: ").append(paddingMethod == 2 ? "Method 2" : "Method 1").append("\n");

            String arqc = EMVOperations.generateARQC(sk, txData, paddingMethod);
            result.append("➜ ARQC: ").append(arqc).append("\n\n");

            result.append("✅ ARQC generated successfully\n");

            arqcResultArea.setText(result.toString());
            arqcResultArea.setVisible(true);
            arqcResultArea.setManaged(true);

            // Add to history
            java.util.Map<String, String> historyMap = new java.util.HashMap<>();
            historyMap.put("Input", "Data: " + txData.substring(0, Math.min(20, txData.length())) + "...");
            historyMap.put("Output", "ARQC: " + arqc);
            mainController.addToHistory("ARQC Generation", historyMap);

        } catch (Exception e) {
            arqcResultArea.setText("Error: " + e.getMessage());
            arqcResultArea.setVisible(true);
            arqcResultArea.setManaged(true);
        }
    }

    public void handleVerifyARQC() {
        try {
            String sk = skARQCField.getText().trim().replaceAll("\\s+", "");
            String amount = amountField.getText().trim().replaceAll("\\s+", "");
            String arqcToVerify = arqcResultArea.getText();

            // Extract ARQC from result area if it contains the full output
            if (arqcToVerify.contains("ARQC: ")) {
                int start = arqcToVerify.indexOf("ARQC: ") + 6;
                int end = arqcToVerify.indexOf("\n", start);
                if (end == -1)
                    end = arqcToVerify.length();
                arqcToVerify = arqcToVerify.substring(start, end).trim();
            }

            if (sk.isEmpty() || arqcToVerify.isEmpty() || arqcToVerify.length() != 16) {
                arqcResultArea.setText("Error: Please generate an ARQC first to verify");
                return;
            }

            // Rebuild transaction data
            String currency = currencyField.getText().trim().replaceAll("\\s+", "");
            String country = countryField.getText().trim().replaceAll("\\s+", "");
            String atc = atcARQCField.getText().trim().replaceAll("\\s+", "");
            String tvr = tvrField.getText().trim().replaceAll("\\s+", "");
            String txDate = txDateField.getText().trim().replaceAll("\\s+", "");
            String txType = txTypeField.getText().trim().replaceAll("\\s+", "");
            String un = unField.getText().trim().replaceAll("\\s+", "");

            if (currency.isEmpty())
                currency = "0978";
            if (country.isEmpty())
                country = "0724";
            if (tvr.isEmpty())
                tvr = "0000000000";
            if (txDate.isEmpty())
                txDate = "251207";
            if (txType.isEmpty())
                txType = "00";
            if (un.isEmpty())
                un = "12345678";

            String txData = EMVOperations.buildARQCData(
                    amount, currency, country, atc, tvr, txDate, txType, un);

            boolean valid = EMVOperations.verifyARQC(sk, arqcToVerify, txData);

            StringBuilder result = new StringBuilder();
            result.append("ARQC VERIFICATION\n");
            result.append("═════════════════\n\n");
            result.append("ARQC to Verify: ").append(arqcToVerify).append("\n");
            result.append("Session Key: ").append(sk).append("\n\n");

            if (valid) {
                result.append("✅ ARQC IS VALID\n");
                result.append("\nThe cryptogram is authentic and the transaction data has not been tampered with.\n");
            } else {
                result.append("❌ ARQC IS INVALID\n");
                result.append("\nThe cryptogram does not match. Possible reasons:\n");
                result.append("- Wrong session key\n");
                result.append("- Transaction data has been modified\n");
                result.append("- ARQC was generated with different parameters\n");
            }

            arqcResultArea.setText(result.toString());
            arqcResultArea.setVisible(true);
            arqcResultArea.setManaged(true);

        } catch (Exception e) {
            arqcResultArea.setText("Error during verification: " + e.getMessage());
        }
    }

    // ============================================================================
    // ARPC GENERATION
    // ============================================================================

    public void handleGenerateARPC() {
        try {
            String sk = skARPCField.getText().trim().replaceAll("\\s+", "");
            String arqc = arqcField.getText().trim().replaceAll("\\s+", "");
            String arc = arcField.getText().trim().replaceAll("\\s+", "");
            String csu = csuField.getText().trim().replaceAll("\\s+", "");

            if (sk.isEmpty() || arqc.isEmpty() || arc.isEmpty()) {
                arpcResultArea.setText("Error: Session Key, ARQC, and ARC are required");
                return;
            }

            StringBuilder result = new StringBuilder();
            result.append("ARPC GENERATION (Authorization Response Cryptogram)\n");
            result.append("═══════════════════════════════════════════════════\n\n");

            String selectedMethod = arpcMethodCombo.getSelectionModel().getSelectedItem();
            String arpc;

            if (selectedMethod.contains("Method 1")) {
                result.append("Method: Method 1 (ARPC = Encrypt(ARQC ⊕ ARC))\n");
                result.append("──────────────────────────────────────────────\n");
                result.append("Session Key: ").append(sk).append("\n");
                result.append("ARQC: ").append(arqc).append("\n");
                result.append("ARC: ").append(arc).append("\n\n");

                arpc = EMVOperations.generateARPC_Method1(sk, arqc, arc);

            } else {
                result.append("Method: Method 2 (CSU Method)\n");
                result.append("─────────────────────────────\n");
                result.append("Session Key: ").append(sk).append("\n");
                result.append("ARC: ").append(arc).append("\n");
                result.append("CSU: ").append(csu.isEmpty() ? "00000000" : csu).append("\n\n");

                arpc = EMVOperations.generateARPC_Method2(sk, arc, csu.isEmpty() ? "00000000" : csu);
            }

            result.append("➜ ARPC: ").append(arpc).append("\n\n");
            result.append("✅ ARPC generated successfully\n");
            result.append("\nℹ️  Send this ARPC to the card in the authorization response (Tag 91)\n");

            arpcResultArea.setText(result.toString());
            arpcResultArea.setVisible(true);
            arpcResultArea.setManaged(true);

            // Add to history
            java.util.Map<String, String> historyMap = new java.util.HashMap<>();
            historyMap.put("Input", "ARQC: " + arqc + ", ARC: " + arc);
            historyMap.put("Output", "ARPC: " + arpc);
            mainController.addToHistory("ARPC Generation", historyMap);

        } catch (Exception e) {
            arpcResultArea.setText("Error: " + e.getMessage());
            arpcResultArea.setVisible(true);
            arpcResultArea.setManaged(true);
        }
    }

    // ============================================================================
    // TRACK 2 OPERATIONS
    // ============================================================================

    public void handleEncodeTrack2() {
        try {
            String pan = panTrack2Field.getText().trim().replaceAll("\\s+", "");
            String expiry = expiryTrack2Field.getText().trim();
            String serviceCode = serviceCodeFieldTrack2.getText().trim();
            String discretionaryData = discretionaryDataField.getText().trim();

            if (pan.isEmpty() || expiry.isEmpty() || serviceCode.isEmpty()) {
                track2ResultArea.setText("Error: PAN, Expiry Date, and Service Code are required");
                return;
            }

            StringBuilder result = new StringBuilder();
            result.append("TRACK 2 ENCODING\n");
            result.append("════════════════\n\n");

            String track2 = EMVOperations.encodeTrack2(pan, expiry, serviceCode, discretionaryData);

            result.append("Input Data:\n");
            result.append("───────────\n");
            result.append("PAN: ").append(pan).append("\n");
            result.append("Expiry: ").append(expiry).append(" (YYMM)\n");
            result.append("Service Code: ").append(serviceCode).append("\n");
            if (!discretionaryData.isEmpty()) {
                result.append("Discretionary Data: ").append(discretionaryData).append("\n");
            }
            result.append("\n");

            result.append("Track 2 Equivalent Data:\n");
            result.append("────────────────────────\n");
            result.append(track2).append("\n\n");

            result.append("Format: PAN + 'D' + Expiry + Service Code + Discretionary Data\n");
            result.append("✅ Track 2 encoded successfully\n");

            track2ResultArea.setText(result.toString());
            track2ResultArea.setVisible(true);
            track2ResultArea.setManaged(true);

            // Add to history
            java.util.Map<String, String> historyMap = new java.util.HashMap<>();
            historyMap.put("Input", "PAN: " + pan);
            historyMap.put("Output", "Track 2: " + track2);
            mainController.addToHistory("Track 2 Encoding", historyMap);

        } catch (Exception e) {
            track2ResultArea.setText("Error: " + e.getMessage());
        }
    }

    public void handleDecodeTrack2() {
        try {
            String track2Input = track2InputField.getText().trim().replaceAll("\\s+", "");

            if (track2Input.isEmpty()) {
                track2ResultArea.setText("Error: Track 2 data is required");
                return;
            }

            String result = EMVOperations.decodeTrack2(track2Input);
            track2ResultArea.setText(result);
            track2ResultArea.setVisible(true);
            track2ResultArea.setManaged(true);

            // Add to history
            java.util.Map<String, String> historyMap = new java.util.HashMap<>();
            historyMap.put("Input", "Track 2: " + track2Input.substring(0, Math.min(20, track2Input.length())) + "...");
            historyMap.put("Output", "Decoded successfully");
            mainController.addToHistory("Track 2 Decoding", historyMap);

        } catch (Exception e) {
            track2ResultArea.setText("Error: " + e.getMessage());
        }
    }

    // --- Helper Methods for Global Toolbar ---

    public void handleClear() {
        // Clear Result Areas
        if (sessionKeyResultArea != null)
            sessionKeyResultArea.clear();
        if (arqcResultArea != null)
            arqcResultArea.clear();
        if (arpcResultArea != null)
            arpcResultArea.clear();
        if (track2ResultArea != null)
            track2ResultArea.clear();

        // Clear Inputs (Session Key)
        if (imkField != null)
            imkField.clear();
        if (panFieldSession != null)
            panFieldSession.clear();
        if (panSeqFieldSession != null)
            panSeqFieldSession.clear();
        if (atcField != null)
            atcField.clear();

        // Clear Inputs (ARQC)
        if (skARQCField != null)
            skARQCField.clear();
        if (amountField != null)
            amountField.clear();
        if (amountOtherField != null)
            amountOtherField.clear();
        if (atcARQCField != null)
            atcARQCField.clear();
        if (unField != null)
            unField.clear();
        if (arqcTerminalDataField != null)
            arqcTerminalDataField.clear();
        if (iccDataField != null)
            iccDataField.clear();

        // Clear Inputs (ARPC)
        if (skARPCField != null)
            skARPCField.clear();
        if (arqcField != null)
            arqcField.clear();
        if (arcField != null)
            arcField.clear();
        if (csuField != null)
            csuField.clear();
        if (propAuthDataField != null)
            propAuthDataField.clear();

        // Clear Inputs (Track2)
        if (panTrack2Field != null)
            panTrack2Field.clear();
        if (expiryTrack2Field != null)
            expiryTrack2Field.clear();
        if (serviceCodeFieldTrack2 != null)
            serviceCodeFieldTrack2.clear();
        if (discretionaryDataField != null)
            discretionaryDataField.clear();
        if (track2InputField != null)
            track2InputField.clear();
    }

    public String getOutputText() {
        if (arpcResultArea != null && !arpcResultArea.getText().isEmpty()) {
            return arpcResultArea.getText();
        }
        if (arqcResultArea != null && !arqcResultArea.getText().isEmpty()) {
            return arqcResultArea.getText();
        }
        if (track2ResultArea != null && !track2ResultArea.getText().isEmpty()) {
            return track2ResultArea.getText();
        }
        if (sessionKeyResultArea != null && !sessionKeyResultArea.getText().isEmpty()) {
            return sessionKeyResultArea.getText();
        }
        return "";
    }

    public String getArpcResultText() {
        return arpcResultArea != null ? arpcResultArea.getText() : "";
    }
}
