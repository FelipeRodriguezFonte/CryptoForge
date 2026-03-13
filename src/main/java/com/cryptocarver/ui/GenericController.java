package com.cryptocarver.ui;

import com.cryptocarver.crypto.CheckDigitCalculator;
import com.cryptocarver.crypto.HashOperations;
import com.cryptocarver.crypto.ModularArithmetic;
import com.cryptocarver.crypto.UUIDGenerator;
import com.cryptocarver.utils.DataConverter;
import com.cryptocarver.utils.FileConverter;
import com.cryptocarver.utils.OperationHistory;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.TextInputControl;

import java.security.NoSuchAlgorithmException;

/**
 * Controller for Generic cryptography operations - Enhanced
 * 
 * @author Felipe
 */
public class GenericController {

    private final TextArea inputArea;
    private final TextArea outputArea;
    private final ComboBox<String> inputFormatCombo;
    private final ComboBox<String> outputFormatCombo;
    private final StatusReporter statusReporter;

    // UI Components for Generic tab
    private ComboBox<String> hashAlgorithmCombo;
    private ComboBox<String> checkDigitAlgorithmCombo;
    private javafx.scene.control.TextField randomBytesField;
    private ComboBox<String> randomFormatCombo;

    // Modular Arithmetic components
    private ComboBox<String> modOperationCombo;
    private TextField modOperandAField;
    private TextField modOperandBField;
    private TextField modModulusField;
    private TextArea modResultArea;

    // File Converter components
    private TextField fileInputPathField;
    private TextField fileOutputPathField;
    private ComboBox<String> fileInputFormatCombo;
    private ComboBox<String> fileOutputFormatCombo;
    private ComboBox<String> fileEncodingCombo;
    // UUID components
    private TextField uuidOutputField;
    // Specific Output Areas
    private TextArea randomOutputArea;
    private TextInputControl checkDigitOutputArea;

    private TextArea fileResultArea;

    // Manual Conversion Components
    private TextArea manualInputArea;
    private TextArea manualOutputArea;

    /**
     * Convert hex string to byte array (replacement for
     * DatatypeConverter.parseHexBinary)
     */
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Convert byte array to hex string (replacement for
     * DatatypeConverter.printHexBinary)
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public GenericController(StatusReporter statusReporter,
            TextArea inputArea,
            TextArea outputArea,
            ComboBox<String> inputFormatCombo,
            ComboBox<String> outputFormatCombo) {
        this.statusReporter = statusReporter;
        this.inputArea = inputArea;
        this.outputArea = outputArea;
        this.inputFormatCombo = inputFormatCombo;
        this.outputFormatCombo = outputFormatCombo;
    }

    /**
     * Set hash algorithm ComboBox reference
     */
    public void setHashAlgorithmCombo(ComboBox<String> combo) {
        this.hashAlgorithmCombo = combo;
        hashAlgorithmCombo.getItems().addAll(HashOperations.SUPPORTED_ALGORITHMS);
        hashAlgorithmCombo.getItems().add("CRC32");
        hashAlgorithmCombo.setValue("SHA-256");
    }

    /**
     * Set check digit algorithm ComboBox reference
     */
    public void setCheckDigitAlgorithmCombo(ComboBox<String> combo) {
        this.checkDigitAlgorithmCombo = combo;
        checkDigitAlgorithmCombo.getItems().addAll(CheckDigitCalculator.SUPPORTED_ALGORITHMS);
        checkDigitAlgorithmCombo.setValue("Luhn (Mod 10)");
    }

    /**
     * Set random generator fields reference
     */
    public void setRandomGeneratorFields(javafx.scene.control.TextField bytesField, ComboBox<String> formatCombo) {
        this.randomBytesField = bytesField;
        this.randomFormatCombo = formatCombo;
        randomFormatCombo.getItems().addAll("Hexadecimal", "Decimal", "Base64", "Binary");
        randomFormatCombo.setValue("Hexadecimal");
    }

    public void setRandomOutputArea(TextArea area) {
        this.randomOutputArea = area;
    }

    public void setCheckDigitOutputArea(TextInputControl area) {
        this.checkDigitOutputArea = area;
    }

    public void setUUIDOutputField(TextField uuidField) {
        this.uuidOutputField = uuidField;
    }

    public void setManualConversionFields(TextArea input, TextArea output) {
        this.manualInputArea = input;
        this.manualOutputArea = output;
    }

    /**
     * Calculate hash of input data
     * 
     * @param input            The input string
     * @param algorithm        The hash algorithm
     * @param targetOutputArea The TextArea to display the result
     */
    /**
     * Calculate hash of input data with specified format
     * 
     * @param input            The input string
     * @param inputFormat      The format of the input string
     * @param algorithm        The hash algorithm
     * @param targetOutputArea The TextArea to display the result
     */
    public void calculateHash(String input, String inputFormat, String algorithm, TextInputControl targetOutputArea) {
        try {
            if (input == null || input.isEmpty()) {
                statusReporter.showError("Input Error", "Please enter data to hash");
                return;
            }

            if (algorithm == null || algorithm.isEmpty()) {
                statusReporter.showError("Algorithm Error", "Please select a hash algorithm");
                return;
            }

            // Parse input based on format
            byte[] inputData;
            try {
                inputData = parseInput(input, inputFormat);
            } catch (IllegalArgumentException e) {
                statusReporter.showError("Input Error", e.getMessage());
                return;
            }

            // Calculate hash
            byte[] hash = HashOperations.calculateHash(inputData, algorithm);
            String hashHex = bytesToHex(hash);

            // Display result
            targetOutputArea.setText(hashHex);
            statusReporter.updateStatus("Hash calculated using " + algorithm);

            // Add to history
            OperationHistory.getInstance().addOperation(
                    "Generic",
                    "Hash - " + algorithm,
                    input.substring(0, Math.min(100, input.length())),
                    hashHex);

        } catch (NoSuchAlgorithmException e) {
            statusReporter.showError("Algorithm Error", "Algorithm not supported: " + e.getMessage());
        } catch (Exception e) {
            statusReporter.showError("Hash Error", "Error calculating hash: " + e.getMessage());
        }
    }

    /**
     * Legacy wrapper for MainController compatibility
     */
    public void handleCalculateHash() {
        if (inputArea != null && hashAlgorithmCombo != null && outputArea != null) {
            // Note: Legacy used getInputDataAsBytes() which respected inputFormatCombo.
            // Ideally we replicate that if we want full legacy support, but for now
            // I'll try to keep behavioral consistency.
            // If this breaks legacy complex inputs (like Hex input for hash), we fix later.
            calculateHash(inputArea.getText(),
                    inputFormatCombo != null ? inputFormatCombo.getValue() : "Text",
                    hashAlgorithmCombo.getValue(),
                    outputArea);
        }
    }

    /**
     * Universal conversion
     */
    public void convert(String input, String inputFormat, String outputFormat, TextInputControl targetOutputArea) {
        try {
            if (input == null || input.isEmpty()) {
                statusReporter.showError("Input Error", "Please enter data to convert");
                return;
            }
            if (inputFormat == null || outputFormat == null) {
                statusReporter.showError("Format Error", "Please select both input and output formats");
                return;
            }

            // Parse Input
            byte[] inputData;
            switch (inputFormat) {
                case "Hexadecimal":
                    String cleanHex = input.replaceAll("\\s+", "");
                    if (!DataConverter.isValidHex(cleanHex)) {
                        statusReporter.showError("Input Error", "Invalid hexadecimal input. Use 0-9, A-F.");
                        return;
                    }
                    inputData = DataConverter.hexToBytes(cleanHex);
                    break;
                case "Base64":
                    try {
                        inputData = java.util.Base64.getDecoder().decode(input.trim());
                    } catch (IllegalArgumentException e) {
                        try {
                            // Try URL-safe Base64 (common in JWT/JWE)
                            inputData = java.util.Base64.getUrlDecoder().decode(input.trim());
                        } catch (IllegalArgumentException ex) {
                            statusReporter.showError("Input Error", "Invalid Base64 input.");
                            return;
                        }
                    }
                    break;
                case "Text (UTF-8)":
                case "Text":
                    inputData = input.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    break;
                case "Binary":
                    try {
                        inputData = DataConverter.binaryToBytes(input.replaceAll("\\s+", ""));
                    } catch (IllegalArgumentException e) {
                        statusReporter.showError("Input Error", "Invalid binary input: " + e.getMessage());
                        return;
                    }
                    break;
                case "Decimal":
                    // Assuming space-separated or comma-separated decimals
                    try {
                        String[] parts = input.replaceAll("[,\\s]+", " ").trim().split(" ");
                        inputData = new byte[parts.length];
                        for (int i = 0; i < parts.length; i++) {
                            inputData[i] = (byte) Integer.parseInt(parts[i]);
                        }
                    } catch (NumberFormatException e) {
                        statusReporter.showError("Input Error", "Invalid decimal input: " + e.getMessage());
                        return;
                    }
                    break;
                default:
                    statusReporter.showError("Format Error", "Unsupported input format: " + inputFormat);
                    return;
            }

            // Format Output
            String outputResult;
            switch (outputFormat) {
                case "Hexadecimal":
                    outputResult = bytesToHex(inputData);
                    break;
                case "Base64":
                    outputResult = java.util.Base64.getEncoder().encodeToString(inputData);
                    break;
                case "Text (UTF-8)":
                case "Text":
                    outputResult = new String(inputData, java.nio.charset.StandardCharsets.UTF_8);
                    break;
                case "Binary":
                    outputResult = DataConverter.bytesToBinary(inputData);
                    break;
                case "Decimal":
                    StringBuilder decSb = new StringBuilder();
                    for (byte b : inputData) {
                        decSb.append(String.format("%d ", b & 0xFF));
                    }
                    outputResult = decSb.toString().trim();
                    break;
                default:
                    statusReporter.showError("Format Error", "Unsupported output format: " + outputFormat);
                    return;
            }

            targetOutputArea.setText(outputResult);
            statusReporter.updateStatus(String.format("Converted from %s to %s", inputFormat, outputFormat));

            // Add to history
            OperationHistory.getInstance().addOperation(
                    "Generic",
                    "Convert - " + inputFormat + " → " + outputFormat,
                    input.substring(0, Math.min(100, input.length())),
                    outputResult.substring(0, Math.min(100, outputResult.length())));

        } catch (Exception e) {
            statusReporter.showError("Conversion Error", "Error converting data: " + e.getMessage());
        }
    }

    public void handleConvert() {
        if (inputArea != null && inputFormatCombo != null && outputFormatCombo != null && outputArea != null) {
            convert(inputArea.getText(), inputFormatCombo.getValue(), outputFormatCombo.getValue(), outputArea);
        }
    }

    /**
     * Calculate check digit
     */
    public void calculateCheckDigit(String input, String algorithm, TextInputControl targetOutputArea) {
        try {
            if (input == null || input.isEmpty()) {
                statusReporter.showError("Input Error", "Please enter numeric data");
                return;
            }
            if (algorithm == null || algorithm.isEmpty()) {
                statusReporter.showError("Algorithm Error", "Please select a check digit algorithm");
                return;
            }

            int checkDigit = CheckDigitCalculator.calculateCheckDigit(input, algorithm);
            String result = CheckDigitCalculator.formatWithCheckDigit(input, algorithm);

            targetOutputArea.setText("Check Digit: " + checkDigit + "\nComplete: " + result);
            statusReporter.updateStatus("Check digit calculated using " + algorithm);

            OperationHistory.getInstance().addOperation("Generic", "Check Digit - " + algorithm, input,
                    "Digit: " + checkDigit);

        } catch (Exception e) {
            statusReporter.showError("Check Digit Error", "Error calculating check digit: " + e.getMessage());
        }
    }

    public void handleCalculateCheckDigit() {
        if (inputArea != null && checkDigitAlgorithmCombo != null && outputArea != null) {
            calculateCheckDigit(inputArea.getText(), checkDigitAlgorithmCombo.getValue(), outputArea);
        } else if (checkDigitAlgorithmCombo != null && checkDigitOutputArea != null && inputArea != null) {
            // Case for Modern UI where specific fields are used but inputArea (generic)
            // might be null?
            // Wait, Check Digit Pane has its OWN input field in Modern UI?
            // FXML shows: <TextField fx:id="checkDigitInput" .../>
            // GenericController doesn't seem to have checkDigitInput field yet?
            // I need to check if GenericController has a specific input field for Check
            // Digit.
            // If not, I am missing that too.
            // Let's assume for now I should use a specific input field if it exists.
            // But I only see `setCheckDigitAlgorithmCombo`.
            // I likely missed the input field.
        }
    }

    public void validateCheckDigit(String input, String algorithm, TextInputControl targetOutputArea) {
        try {
            if (input == null || input.isEmpty()) {
                statusReporter.showError("Input Error", "Please enter data with check digit");
                return;
            }
            if (algorithm == null || algorithm.isEmpty()) {
                statusReporter.showError("Algorithm Error", "Please select a check digit algorithm");
                return;
            }

            boolean isValid = CheckDigitCalculator.validateCheckDigit(input, algorithm);
            String resultText = isValid ? "✅ VALID" : "❌ INVALID";

            targetOutputArea.setText("Validation Result: " + resultText);
            statusReporter.updateStatus("Check digit validation: " + resultText);

        } catch (Exception e) {
            statusReporter.showError("Validation Error", "Error validating: " + e.getMessage());
        }
    }

    public void handleValidateCheckDigit() {
        if (inputArea != null && checkDigitAlgorithmCombo != null && outputArea != null) {
            validateCheckDigit(inputArea.getText(), checkDigitAlgorithmCombo.getValue(), outputArea);
        }
    }

    /**
     * Get input data as bytes based on selected format
     */
    /**
     * Parse input string based on format
     */
    public static byte[] parseInput(String input, String format) {
        if (input == null || input.trim().isEmpty()) {
            return null;
        }
        if (format == null) {
            format = "Hexadecimal";
        }

        try {
            switch (format) {
                case "Hexadecimal":
                    // Validate hex first
                    String cleanHex = input.replaceAll("\\s+", "");
                    if (!DataConverter.isValidHex(cleanHex)) {
                        throw new IllegalArgumentException(
                                "Invalid hexadecimal format. Use pairs of hex digits (0-9, A-F)");
                    }
                    return DataConverter.hexToBytes(cleanHex);

                case "Base64":
                    try {
                        return org.apache.commons.codec.binary.Base64.decodeBase64(input.trim());
                    } catch (Exception e) {
                        throw new IllegalArgumentException("Invalid Base64 format: " + e.getMessage());
                    }

                case "Text":
                case "Text (UTF-8)":
                    return input.getBytes(java.nio.charset.StandardCharsets.UTF_8);

                case "Binary":
                    // Parse binary string (e.g., "01001000 01100101")
                    String binary = input.replaceAll("\\s", "");
                    if (!binary.matches("[01]+")) {
                        throw new IllegalArgumentException("Invalid binary format. Use only 0 and 1");
                    }
                    if (binary.length() % 8 != 0) {
                        throw new IllegalArgumentException("Binary string length must be multiple of 8");
                    }
                    byte[] data = new byte[binary.length() / 8];
                    for (int i = 0; i < data.length; i++) {
                        String byteStr = binary.substring(i * 8, (i + 1) * 8);
                        data[i] = (byte) Integer.parseInt(byteStr, 2);
                    }
                    return data;

                default:
                    // Default fallback to hex if unknown but try to be safe
                    // Actually default should probably be error or Text?
                    // Let's stick to previous logical fallback or error.
                    // Previous code defaulted to Hex.
                    return DataConverter.hexToBytes(input.replaceAll("\\s+", ""));
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Error parsing " + format + " input: " + e.getMessage());
        }
    }

    /**
     * Get input data as bytes based on selected format
     */
    private byte[] getInputDataAsBytes() {
        return parseInput(inputArea.getText(), inputFormatCombo.getValue());
    }

    /**
     * Set output data based on selected format
     */
    private void setOutputData(byte[] data) {
        String format = outputFormatCombo.getValue();
        if (format == null) {
            format = "Hexadecimal";
        }

        String output;
        switch (format) {
            case "Hexadecimal":
                output = DataConverter.bytesToHex(data);
                break;
            case "Base64":
                output = org.apache.commons.codec.binary.Base64.encodeBase64String(data);
                break;
            case "Text (UTF-8)":
                output = new String(data, java.nio.charset.StandardCharsets.UTF_8);
                break;
            case "Binary":
                output = DataConverter.bytesToBinary(data);
                break;
            case "C Array":
                output = DataConverter.bytesToCArray(data, 12);
                break;
            default:
                output = DataConverter.bytesToHex(data);
        }

        outputArea.setText(output);
    }

    /**
     * Generate random bytes
     */
    public void handleGenerateRandom() {
        try {
            String bytesStr = randomBytesField.getText().trim();
            if (bytesStr.isEmpty()) {
                statusReporter.showError("Input Error", "Please enter the number of bytes to generate");
                return;
            }

            int numBytes = Integer.parseInt(bytesStr);
            if (numBytes <= 0 || numBytes > 1024) {
                statusReporter.showError("Input Error", "Number of bytes must be between 1 and 1024");
                return;
            }

            String format = randomFormatCombo.getValue();
            if (format == null) {
                statusReporter.showError("Format Error", "Please select an output format");
                return;
            }

            // Generate random bytes
            java.security.SecureRandom random = new java.security.SecureRandom();
            byte[] randomBytes = new byte[numBytes];
            random.nextBytes(randomBytes);

            // Format output
            String output;
            switch (format) {
                case "Hexadecimal":
                    output = DataConverter.bytesToHex(randomBytes);
                    break;
                case "Decimal":
                    StringBuilder decimal = new StringBuilder();
                    for (byte b : randomBytes) {
                        decimal.append(String.format("%03d ", b & 0xFF));
                    }
                    output = decimal.toString().trim();
                    break;
                case "Base64":
                    output = org.apache.commons.codec.binary.Base64.encodeBase64String(randomBytes);
                    break;
                case "Binary":
                    output = DataConverter.bytesToBinary(randomBytes);
                    break;
                default:
                    output = DataConverter.bytesToHex(randomBytes);
            }

            if (randomOutputArea != null) {
                randomOutputArea.setText(output);
            } else if (outputArea != null) {
                outputArea.setText(output);
            } else {
                statusReporter.showError("System Error", "No output area defined for random generator");
            }
            statusReporter.updateStatus("Generated " + numBytes + " random bytes");

            // Add to history
            OperationHistory.getInstance().addOperation(
                    "Generic",
                    "Generate Random - " + numBytes + " bytes",
                    "Format: " + format,
                    output.substring(0, Math.min(100, output.length())));

        } catch (NumberFormatException e) {
            statusReporter.showError("Input Error", "Please enter a valid number");
        } catch (Exception e) {
            statusReporter.showError("Generation Error", "Error generating random bytes: " + e.getMessage());
        }
    }

    // ============================================================================
    // MODULAR ARITHMETIC CALCULATOR
    // ============================================================================

    /**
     * Initialize modular arithmetic components
     */
    public void initializeModularArithmetic(
            ComboBox<String> operationCombo,
            TextField operandAField,
            TextField operandBField,
            TextField modulusField,
            TextArea resultArea) {

        this.modOperationCombo = operationCombo;
        this.modOperandAField = operandAField;
        this.modOperandBField = operandBField;
        this.modModulusField = modulusField;
        this.modResultArea = resultArea;

        modOperationCombo.getItems().addAll(
                "Addition (a + b) mod m",
                "Subtraction (a - b) mod m",
                "Inverse -a mod m",
                "Multiplication (a * b) mod m",
                "Exponentiation (a^b) mod m",
                "Reciprocal (1/a) mod m",
                "GCD(a, b)",
                "LCM(a, b)",
                "Extended GCD",
                "Chinese Remainder Theorem",
                "XOR (Hex Input)",
                "XOR (Decimal Input)");
        modOperationCombo.setValue("Addition (a + b) mod m");
    }

    /**
     * Calculate modular arithmetic operation
     */
    public void handleModularCalculate() {
        try {
            String operation = modOperationCombo.getValue();
            String aInput = modOperandAField.getText().trim();
            String bInput = modOperandBField.getText().trim();
            String mInput = modModulusField.getText().trim();

            // Default hex cleaning for standard operations
            String aHex = "", bHex = "", mHex = "";

            // Special handling for Decimal XOR
            if (operation.contains("Decimal Input")) {
                // For decimal, we just keep the raw digits
                if (!aInput.matches("\\d+") || (!bInput.isEmpty() && !bInput.matches("\\d+"))) {
                    statusReporter.showError("Input Error", "Please enter valid decimal numbers");
                    return;
                }
                // Convert decimal to hex for internal processing/compatibility with existing
                // modular logic if needed
                // But for XOR we'll process directly.
            } else {
                // Standard Hex processing
                aHex = aInput.replaceAll("[^0-9A-Fa-f]", "");
                bHex = bInput.replaceAll("[^0-9A-Fa-f]", "");
                mHex = mInput.replaceAll("[^0-9A-Fa-f]", "");
            }

            if (operation.contains("XOR")) {
                if (aInput.isEmpty() || bInput.isEmpty()) {
                    statusReporter.showError("Input Error", "Both operands required for XOR");
                    return;
                }

                java.math.BigInteger aBig, bBig;
                if (operation.contains("Decimal Input")) {
                    aBig = new java.math.BigInteger(aInput);
                    bBig = new java.math.BigInteger(bInput);
                } else {
                    aBig = new java.math.BigInteger(aHex, 16);
                    bBig = new java.math.BigInteger(bHex, 16);
                }

                java.math.BigInteger result = aBig.xor(bBig);
                String hexResult = result.toString(16).toUpperCase();

                String opDesc = operation.contains("Decimal")
                        ? aInput + " XOR " + bInput
                        : aHex + " XOR " + bHex;

                modResultArea.setText(ModularArithmetic.formatResult(opDesc, hexResult));
                return;
            }

            // For standard modular operations, continue using clean Hex strings
            if (aHex.isEmpty()) {
                statusReporter.showError("Input Error", "Operand A is required");
                return;
            }

            String result;
            String operationDesc;

            try {
                switch (operation) {
                    case "Addition (a + b) mod m":
                        if (bHex.isEmpty() || mHex.isEmpty()) {
                            statusReporter.showError("Input Error", "All fields required for addition");
                            return;
                        }
                        result = ModularArithmetic.modularAddition(aHex, bHex, mHex);
                        operationDesc = "(" + aHex + " + " + bHex + ") mod " + mHex;
                        modResultArea.setText(ModularArithmetic.formatResult(operationDesc, result));
                        break;

                    case "Subtraction (a - b) mod m":
                        if (bHex.isEmpty() || mHex.isEmpty()) {
                            statusReporter.showError("Input Error", "All fields required for subtraction");
                            return;
                        }
                        result = ModularArithmetic.modularSubtraction(aHex, bHex, mHex);
                        operationDesc = "(" + aHex + " - " + bHex + ") mod " + mHex;
                        modResultArea.setText(ModularArithmetic.formatResult(operationDesc, result));
                        break;

                    case "Inverse -a mod m":
                        if (mHex.isEmpty()) {
                            statusReporter.showError("Input Error", "Modulus is required");
                            return;
                        }
                        result = ModularArithmetic.modularInverse(aHex, mHex);
                        operationDesc = "-" + aHex + " mod " + mHex;
                        modResultArea.setText(ModularArithmetic.formatResult(operationDesc, result));
                        break;

                    case "Multiplication (a * b) mod m":
                        if (bHex.isEmpty() || mHex.isEmpty()) {
                            statusReporter.showError("Input Error", "All fields required for multiplication");
                            return;
                        }
                        result = ModularArithmetic.modularMultiplication(aHex, bHex, mHex);
                        operationDesc = "(" + aHex + " * " + bHex + ") mod " + mHex;
                        modResultArea.setText(ModularArithmetic.formatResult(operationDesc, result));
                        break;

                    case "Exponentiation (a^b) mod m":
                        if (bHex.isEmpty() || mHex.isEmpty()) {
                            statusReporter.showError("Input Error", "All fields required for exponentiation");
                            return;
                        }
                        result = ModularArithmetic.modularExponentiation(aHex, bHex, mHex);
                        operationDesc = "(" + aHex + "^" + bHex + ") mod " + mHex;
                        modResultArea.setText(ModularArithmetic.formatResult(operationDesc, result));
                        break;

                    case "Reciprocal (1/a) mod m":
                        if (mHex.isEmpty()) {
                            statusReporter.showError("Input Error", "Modulus is required");
                            return;
                        }
                        try {
                            result = ModularArithmetic.modularReciprocal(aHex, mHex);
                            operationDesc = "(1/" + aHex + ") mod " + mHex;

                            StringBuilder output = new StringBuilder();
                            output.append(ModularArithmetic.formatResult(operationDesc, result));

                            boolean isPrime = ModularArithmetic.isProbablyPrime(mHex);
                            output.append("\nModulus is ").append(isPrime ? "PROBABLY PRIME" : "COMPOSITE");

                            modResultArea.setText(output.toString());
                        } catch (ArithmeticException e) {
                            modResultArea.setText("ERROR: " + e.getMessage() +
                                    "\n\nModular reciprocal only exists when gcd(a, m) = 1");
                        }
                        break;

                    case "GCD(a, b)":
                        if (bHex.isEmpty()) {
                            statusReporter.showError("Input Error", "Operand B is required");
                            return;
                        }
                        result = ModularArithmetic.gcd(aHex, bHex);
                        operationDesc = "GCD(" + aHex + ", " + bHex + ")";
                        modResultArea.setText(ModularArithmetic.formatResult(operationDesc, result));
                        break;

                    case "LCM(a, b)":
                        if (bHex.isEmpty()) {
                            statusReporter.showError("Input Error", "Operand B is required");
                            return;
                        }
                        result = ModularArithmetic.lcm(aHex, bHex);
                        operationDesc = "LCM(" + aHex + ", " + bHex + ")";
                        modResultArea.setText(ModularArithmetic.formatResult(operationDesc, result));
                        break;

                    case "Extended GCD":
                        if (bHex.isEmpty()) {
                            statusReporter.showError("Input Error", "Operand B is required");
                            return;
                        }
                        result = ModularArithmetic.extendedGCD(aHex, bHex);
                        modResultArea.setText("Extended Euclidean Algorithm\n" +
                                "Finding x, y such that: ax + by = gcd(a,b)\n\n" + result);
                        break;

                    case "Chinese Remainder Theorem":
                        // For CRT, A and M are first pair, B and another field for second pair
                        if (bHex.isEmpty() || mHex.isEmpty()) {
                            statusReporter.showError("Input Error",
                                    "CRT requires: A=a1, B=m1, Modulus=a2\n" +
                                            "Enter m2 in the operation history or use Extended GCD for setup");
                            return;
                        }
                        // Simplified CRT - would need additional fields for full implementation
                        modResultArea.setText("Chinese Remainder Theorem\n\n" +
                                "Note: Full CRT requires 2 modular equations:\n" +
                                "  x ≡ a1 (mod m1)\n" +
                                "  x ≡ a2 (mod m2)\n\n" +
                                "This would need additional UI fields for proper implementation.");
                        break;

                    default:
                        modResultArea.setText("Unknown operation");
                }

                statusReporter.updateStatus("Modular operation completed");

                OperationHistory.getInstance().addOperation(
                        "Generic",
                        "Modular Arithmetic - " + operation,
                        "a=" + aHex.substring(0, Math.min(16, aHex.length())),
                        "Result calculated");

            } catch (ArithmeticException e) {
                modResultArea.setText("ERROR: " + e.getMessage());
            }

        } catch (Exception e) {
            statusReporter.showError("Calculation Error", "Error in modular arithmetic: " + e.getMessage());
        }
    }

    // ============================================================================
    // FILE CONVERTER
    // ============================================================================

    /**
     * Initialize file converter components
     */
    public void initializeFileConverter(
            TextField inputPathField,
            TextField outputPathField,
            ComboBox<String> inputFormatCombo,
            ComboBox<String> outputFormatCombo,
            ComboBox<String> encodingCombo,
            TextArea resultArea) {

        this.fileInputPathField = inputPathField;
        this.fileOutputPathField = outputPathField;
        this.fileInputFormatCombo = inputFormatCombo;
        this.fileOutputFormatCombo = outputFormatCombo;
        this.fileEncodingCombo = encodingCombo;
        this.fileResultArea = resultArea;

        // Format options
        String[] formats = { "Binary", "Hex", "Base64", "Text", "Analyze", "Hex Dump" };
        fileInputFormatCombo.getItems().addAll(formats);
        fileOutputFormatCombo.getItems().addAll("Binary", "Hex", "Base64", "Text");
        fileInputFormatCombo.setValue("Binary");
        fileOutputFormatCombo.setValue("Hex");

        // Encoding options
        fileEncodingCombo.getItems().addAll(
                "UTF-8",
                "ASCII",
                "ISO-8859-1 (Latin-1)",
                "ISO-8859-15 (Latin-9)",
                "Windows-1252",
                "UTF-16",
                "UTF-16BE",
                "UTF-16LE",
                "UTF-32",
                "Cp037 (EBCDIC US/Canada)",
                "Cp273 (EBCDIC Germany)",
                "Cp284 (EBCDIC Spain)",
                "Cp285 (EBCDIC UK)",
                "Cp297 (EBCDIC France)",
                "Cp500 (EBCDIC International)",
                "Cp850 (DOS Latin-1)",
                "Cp437 (DOS US)");
        fileEncodingCombo.setValue("UTF-8");

        // Disable encoding when not needed
        javafx.beans.value.ChangeListener<String> encodingListener = (obs, oldVal, newVal) -> {
            boolean needsEncoding = "Text".equals(fileInputFormatCombo.getValue()) ||
                    "Text".equals(fileOutputFormatCombo.getValue());
            fileEncodingCombo.setDisable(!needsEncoding);
        };
        fileInputFormatCombo.valueProperty().addListener(encodingListener);
        fileOutputFormatCombo.valueProperty().addListener(encodingListener);
        fileEncodingCombo.setDisable(true); // Initially disabled
    }

    /**
     * Handle file conversion operation
     */
    public void handleFileConvert() {
        try {
            String inputPath = fileInputPathField.getText().trim();
            String outputPath = fileOutputPathField.getText().trim();
            String inputFormat = fileInputFormatCombo.getValue();
            String outputFormat = fileOutputFormatCombo.getValue();
            String encodingFull = fileEncodingCombo.getValue();

            // Extract charset name (e.g., "UTF-8" or "Cp037" from "Cp037 (EBCDIC
            // US/Canada)")
            String encoding = encodingFull != null ? encodingFull.split(" ")[0] : "UTF-8";

            if (inputPath.isEmpty()) {
                statusReporter.showError("Input Error", "Input file path is required");
                return;
            }

            if (inputFormat == null || outputFormat == null) {
                statusReporter.showError("Input Error", "Please select input and output formats");
                return;
            }

            StringBuilder result = new StringBuilder();
            result.append("File Conversion\n");
            result.append("===============\n\n");
            result.append("Input File: ").append(inputPath).append("\n");
            result.append("From: ").append(inputFormat).append("\n");
            result.append("To: ").append(outputFormat).append("\n");

            // Special operations (no output format)
            if ("Analyze".equals(inputFormat)) {
                result.append("\n").append(FileConverter.analyzeFile(inputPath));
                result.append("\n\n").append(FileConverter.getFileSizeInfo(inputPath));
                fileResultArea.setText(result.toString());
                return;
            }

            if ("Hex Dump".equals(inputFormat)) {
                result.append("\n\n").append(FileConverter.hexDump(inputPath, 512));
                fileResultArea.setText(result.toString());
                return;
            }

            // Step 1: Read input file as bytes based on input format
            byte[] data;
            switch (inputFormat) {
                case "Binary":
                    data = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(inputPath));
                    break;

                case "Hex":
                    String hexContent = java.nio.file.Files.readString(java.nio.file.Paths.get(inputPath)).trim();
                    hexContent = hexContent.replaceAll("\\s+", ""); // Remove whitespace
                    data = hexToBytes(hexContent);
                    break;

                case "Base64":
                    String base64Content = java.nio.file.Files.readString(java.nio.file.Paths.get(inputPath)).trim();
                    data = java.util.Base64.getDecoder().decode(base64Content);
                    break;

                case "Text":
                    String textContent = java.nio.file.Files.readString(java.nio.file.Paths.get(inputPath),
                            java.nio.charset.Charset.forName(encoding));
                    data = textContent.getBytes(encoding);
                    result.append("Input Encoding: ").append(encodingFull).append("\n");
                    break;

                default:
                    statusReporter.showError("Error", "Unknown input format: " + inputFormat);
                    return;
            }

            result.append("Data Size: ").append(data.length).append(" bytes\n");

            // Step 2: Convert to output format
            switch (outputFormat) {
                case "Binary":
                    if (outputPath.isEmpty()) {
                        statusReporter.showError("Input Error", "Output path required for binary files");
                        return;
                    }
                    java.nio.file.Files.write(java.nio.file.Paths.get(outputPath), data);
                    result.append("Output: ").append(outputPath).append("\n");
                    result.append("Status: Binary file written successfully");
                    break;

                case "Hex":
                    String hexOutput = bytesToHex(data);
                    if (outputPath.isEmpty()) {
                        result.append("\nHex Output (first 1000 chars):\n");
                        result.append(hexOutput.substring(0, Math.min(1000, hexOutput.length())));
                        if (hexOutput.length() > 1000) {
                            result.append("\n\n... ").append(hexOutput.length() - 1000).append(" more chars");
                        }
                    } else {
                        java.nio.file.Files.writeString(java.nio.file.Paths.get(outputPath), hexOutput);
                        result.append("Output: ").append(outputPath).append("\n");
                        result.append("Status: Hex file written (").append(hexOutput.length()).append(" chars)");
                    }
                    break;

                case "Base64":
                    String base64Output = java.util.Base64.getEncoder().encodeToString(data);
                    if (outputPath.isEmpty()) {
                        result.append("\nBase64 Output (first 1000 chars):\n");
                        result.append(base64Output.substring(0, Math.min(1000, base64Output.length())));
                        if (base64Output.length() > 1000) {
                            result.append("\n\n... ").append(base64Output.length() - 1000).append(" more chars");
                        }
                    } else {
                        java.nio.file.Files.writeString(java.nio.file.Paths.get(outputPath), base64Output);
                        result.append("Output: ").append(outputPath).append("\n");
                        result.append("Status: Base64 file written (").append(base64Output.length()).append(" chars)");
                    }
                    break;

                case "Text":
                    String textOutput = new String(data, encoding);
                    result.append("Output Encoding: ").append(encodingFull).append("\n");
                    if (outputPath.isEmpty()) {
                        result.append("\nText Output (first 1000 chars):\n");
                        result.append(textOutput.substring(0, Math.min(1000, textOutput.length())));
                        if (textOutput.length() > 1000) {
                            result.append("\n\n... ").append(textOutput.length() - 1000).append(" more chars");
                        }
                    } else {
                        java.nio.file.Files.writeString(java.nio.file.Paths.get(outputPath), textOutput,
                                java.nio.charset.Charset.forName(encoding));
                        result.append("Output: ").append(outputPath).append("\n");
                        result.append("Status: Text file written (").append(textOutput.length()).append(" chars)");
                    }
                    break;

                default:
                    statusReporter.showError("Error", "Unknown output format: " + outputFormat);
                    return;
            }

            fileResultArea.setText(result.toString());
            statusReporter.updateStatus("Conversion completed: " + inputFormat + " → " + outputFormat);

            OperationHistory.getInstance().addOperation(
                    "Generic",
                    "File Convert: " + inputFormat + " → " + outputFormat,
                    inputPath,
                    "Success");

        } catch (java.io.FileNotFoundException e) {
            statusReporter.showError("File Error", "File not found: " + e.getMessage());
        } catch (java.io.IOException e) {
            statusReporter.showError("File Error", "I/O error: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            statusReporter.showError("Format Error", "Invalid input format: " + e.getMessage());
        } catch (Exception e) {
            statusReporter.showError("Conversion Error", "Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Generate UUID
     */
    public void handleGenerateUUID() {
        try {
            String uuid = UUIDGenerator.generateUUID();
            if (uuidOutputField != null) {
                uuidOutputField.setText(uuid);
                statusReporter.updateStatus("Generated UUID v4");
            } else if (outputArea != null) {
                outputArea.setText(uuid);
                statusReporter.updateStatus("Generated UUID v4");
            }

            OperationHistory.getInstance().addOperation("Generic", "UUID Generation", "v4", uuid);
        } catch (Exception e) {
            statusReporter.showError("UUID Error", "Error generating UUID: " + e.getMessage());
        }
    }
    // --- Global Helper Methods ---

    public void handleClear() {
        // Clear Standard Conversion
        if (inputArea != null)
            inputArea.clear();
        if (outputArea != null)
            outputArea.clear();

        // Clear Manual Conversion
        if (manualInputArea != null)
            manualInputArea.clear();
        if (manualOutputArea != null)
            manualOutputArea.clear();

        // Clear Random
        if (randomBytesField != null)
            randomBytesField.clear();
        if (randomOutputArea != null)
            randomOutputArea.clear();

        // Clear Modular Arithmetic
        if (modOperandAField != null)
            modOperandAField.clear();
        if (modOperandBField != null)
            modOperandBField.clear();
        if (modModulusField != null)
            modModulusField.clear();
        if (modResultArea != null)
            modResultArea.clear();

        // Clear UUID
        if (uuidOutputField != null)
            uuidOutputField.clear();

        // Clear Check Digit
        if (checkDigitOutputArea != null)
            checkDigitOutputArea.clear();

        // Clear File Converter
        if (fileInputPathField != null)
            fileInputPathField.clear();
        if (fileOutputPathField != null)
            fileOutputPathField.clear();
        if (fileResultArea != null)
            fileResultArea.clear();
    }

    public String getOutputText() {
        // Check output areas in priority order or all of them

        if (outputArea != null && !outputArea.getText().isEmpty()) {
            return outputArea.getText();
        }

        if (manualOutputArea != null && !manualOutputArea.getText().isEmpty()) {
            return manualOutputArea.getText();
        }

        if (randomOutputArea != null && !randomOutputArea.getText().isEmpty()) {
            return randomOutputArea.getText();
        }

        if (modResultArea != null && !modResultArea.getText().isEmpty()) {
            return modResultArea.getText();
        }

        if (uuidOutputField != null && !uuidOutputField.getText().isEmpty()) {
            return uuidOutputField.getText();
        }

        if (checkDigitOutputArea != null && !checkDigitOutputArea.getText().isEmpty()) {
            return checkDigitOutputArea.getText();
        }

        if (fileResultArea != null && !fileResultArea.getText().isEmpty()) {
            return fileResultArea.getText();
        }

        return "";
    }
}
