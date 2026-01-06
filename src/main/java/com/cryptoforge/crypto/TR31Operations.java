package com.cryptoforge.crypto;

/**
 * Wrapper for TR31 implementation
 * Adapts TR31.java interface to KeysController expectations
 */
public class TR31Operations {
    
    /**
     * Wrap a key into TR-31 format
     */
    public static String wrapKey(String kbpk, String key, String usage, char version, char algorithm, char mode, char exportability) throws Exception {
        // Build header with specified version
        HeaderBuilder builder = new HeaderBuilder()
            .version(version)
            .keyUsage(usage)
            .algorithm(algorithm)
            .modeOfUse(mode)
            .exportability(exportability);
        
        String header = builder.build();
        
        // Generate key block
        TR31 tr31 = new TR31(kbpk);
        return tr31.wrap(header, key);
    }
    
    /**
     * Unwrap a TR-31 key block
     */
    public static String unwrapKey(String kbpk, String keyBlock) throws Exception {
        TR31 tr31 = new TR31(kbpk);
        TR31.UnwrapResult result = tr31.unwrap(keyBlock);
        return bytesToHex(result.key);
    }
    
    /**
     * Parse TR-31 header from key block
     */
    public static String parseHeader(String keyBlock) {
        if (keyBlock.length() < 16) {
            return "Invalid key block (too short)";
        }
        
        StringBuilder sb = new StringBuilder();
        sb.append("Version ID: ").append(keyBlock.charAt(0)).append("\n");
        sb.append("Length: ").append(keyBlock.substring(1, 5)).append("\n");
        sb.append("Key Usage: ").append(keyBlock.substring(5, 7)).append("\n");
        sb.append("Algorithm: ").append(keyBlock.charAt(7)).append("\n");
        sb.append("Mode of Use: ").append(keyBlock.charAt(8)).append("\n");
        sb.append("Key Version: ").append(keyBlock.substring(9, 11)).append("\n");
        sb.append("Exportability: ").append(keyBlock.charAt(11)).append("\n");
        sb.append("Optional Blocks: ").append(keyBlock.substring(12, 16));
        
        return sb.toString();
    }
    
    /**
     * Get description for key usage code
     */
    public static String getKeyUsageDescription(String usage) {
        switch (usage) {
            case "B0": return "BDK Base Derivation Key";
            case "B1": return "Initial DUKPT Key";
            case "C0": return "CVK Card Verification Key";
            case "D0": return "Data Encryption (symmetric)";
            case "D1": return "Data Encryption (asymmetric)";
            case "I0": return "Initialization Vector";
            case "K0": return "Key Encryption/Wrapping";
            case "K1": return "TR-31 KBPK";
            case "M0": return "ISO 16609 MAC (algorithm 1)";
            case "M1": return "ISO 9797-1 MAC (algorithm 1)";
            case "M3": return "ISO 9797-1 MAC (algorithm 3 - Retail)";
            case "M5": return "ISO 9797-1 MAC (algorithm 5)";
            case "M6": return "ISO 9797-1 MAC (CMAC)";
            case "M7": return "HMAC";
            case "P0": return "PIN Encryption";
            case "V0": return "PIN Verification (other)";
            case "V1": return "PIN Verification (IBM 3624)";
            case "V2": return "PIN Verification (VISA PVV)";
            case "S0": return "Asymmetric key for digital signature";
            case "E0": return "EMV/Chip Issuer Master Key";
            default: return usage;
        }
    }
    
    /**
     * Get description for algorithm code
     */
    public static String getAlgorithmDescription(char algorithm) {
        switch (algorithm) {
            case 'A': return "AES";
            case 'D': return "DES (single)";
            case 'E': return "Elliptic Curve";
            case 'H': return "HMAC";
            case 'R': return "RSA";
            case 'S': return "DSA";
            case 'T': return "Triple DES (TDES)";
            default: return String.valueOf(algorithm);
        }
    }
    
    /**
     * Get description for mode of use code
     */
    public static String getModeOfUseDescription(char mode) {
        switch (mode) {
            case 'B': return "Both Encrypt & Decrypt";
            case 'C': return "Both Generate & Verify";
            case 'D': return "Decrypt Only";
            case 'E': return "Encrypt Only";
            case 'G': return "Generate Only";
            case 'N': return "No Special Restrictions";
            case 'S': return "Signature Only";
            case 'T': return "Both Sign & Key Transport";
            case 'V': return "Verify Only";
            case 'X': return "Key Derivation";
            case 'Y': return "Create Cryptographic Checksum";
            default: return String.valueOf(mode);
        }
    }
    
    /**
     * Get description for exportability code
     */
    public static String getExportabilityDescription(char exportability) {
        switch (exportability) {
            case 'E': return "Exportable";
            case 'N': return "Non-exportable";
            case 'S': return "Sensitive";
            default: return String.valueOf(exportability);
        }
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
    
    /**
     * TR31Header class for compatibility with KeysController
     */
    public static class TR31Header {
        public String versionId;
        public int keyBlockLength;
        public String keyUsage;
        public String algorithm;
        public String modeOfUse;
        public String keyVersionNumber;
        public String exportability;
        public int numOptionalBlocks;
        public String reserved;
        public String optionalBlocks;
        
        public static TR31Header parse(String keyBlock) throws Exception {
            if (keyBlock.length() < 16) {
                throw new IllegalArgumentException("TR-31 key block too short");
            }
            
            TR31Header header = new TR31Header();
            header.versionId = String.valueOf(keyBlock.charAt(0));
            header.keyBlockLength = Integer.parseInt(keyBlock.substring(1, 5));
            header.keyUsage = keyBlock.substring(5, 7);
            header.algorithm = String.valueOf(keyBlock.charAt(7));
            header.modeOfUse = String.valueOf(keyBlock.charAt(8));
            header.keyVersionNumber = keyBlock.substring(9, 11);
            header.exportability = String.valueOf(keyBlock.charAt(11));
            header.numOptionalBlocks = Integer.parseInt(keyBlock.substring(12, 14), 16);
            header.reserved = keyBlock.substring(14, 16);
            
            // Extract optional blocks if present
            int headerBaseLen = 16;
            if (header.numOptionalBlocks > 0 && keyBlock.length() > headerBaseLen) {
                // Parse optional blocks (simplified - just capture the data)
                int optBlocksEnd = headerBaseLen;
                for (int i = 0; i < header.numOptionalBlocks && optBlocksEnd + 4 <= keyBlock.length(); i++) {
                    int blockLen = Integer.parseInt(keyBlock.substring(optBlocksEnd + 2, optBlocksEnd + 4), 16);
                    optBlocksEnd += 4 + blockLen * 2;
                }
                if (optBlocksEnd <= keyBlock.length()) {
                    header.optionalBlocks = keyBlock.substring(headerBaseLen, optBlocksEnd);
                }
            } else {
                header.optionalBlocks = "";
            }
            
            return header;
        }
        
        /**
         * Build header string (for compatibility)
         */
        public String build() {
            StringBuilder sb = new StringBuilder();
            sb.append(versionId);
            sb.append(String.format("%04d", keyBlockLength));
            sb.append(keyUsage);
            sb.append(algorithm);
            sb.append(modeOfUse);
            sb.append(keyVersionNumber);
            sb.append(exportability);
            sb.append(String.format("%02d", numOptionalBlocks));
            sb.append(reserved);
            if (optionalBlocks != null && !optionalBlocks.isEmpty()) {
                sb.append(optionalBlocks);
            }
            return sb.toString();
        }
    }
}
