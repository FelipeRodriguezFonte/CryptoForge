package com.cryptoforge.util;

/**
 * Utility class for data conversion between different formats
 */
public class DataConverter {
    
    /**
     * Convert hexadecimal string to byte array
     * @param hex Hexadecimal string (e.g., "48656C6C6F")
     * @return Byte array
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[0];
        }
        
        // Remove spaces, newlines, and other whitespace
        hex = hex.replaceAll("\\s+", "");
        
        // Check if valid hex
        if (!hex.matches("[0-9A-Fa-f]+")) {
            throw new IllegalArgumentException("Invalid hexadecimal string");
        }
        
        // Ensure even length
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hexadecimal string must have even length");
        }
        
        int len = hex.length();
        byte[] data = new byte[len / 2];
        
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        
        return data;
    }
    
    /**
     * Convert byte array to hexadecimal string
     * @param bytes Byte array
     * @return Hexadecimal string (uppercase, no spaces)
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        
        return sb.toString();
    }
    
    /**
     * Convert byte array to hexadecimal string with spaces
     * @param bytes Byte array
     * @return Hexadecimal string with spaces (e.g., "48 65 6C 6C 6F")
     */
    public static String bytesToHexWithSpaces(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                sb.append(" ");
            }
            sb.append(String.format("%02X", bytes[i]));
        }
        
        return sb.toString();
    }
}
