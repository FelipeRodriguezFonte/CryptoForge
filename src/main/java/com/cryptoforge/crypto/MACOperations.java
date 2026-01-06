package com.cryptoforge.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

/**
 * Message Authentication Code (MAC) operations
 * Supports: CBC-MAC, HMAC, CMAC, Retail MAC (ISO 9797-1 Algorithm 3)
 * 
 * @author Felipe
 */
public class MACOperations {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Supported MAC algorithms
     */
    public static final String[] SUPPORTED_ALGORITHMS = {
            "HMAC-SHA1",
            "HMAC-SHA256",
            "HMAC-SHA384",
            "HMAC-SHA512",
            "CMAC-AES",
            "CMAC-3DES",
            "CBC-MAC-DES",
            "CBC-MAC-3DES",
            "CBC-MAC-AES",
            "ISO-9797-1-ALG1",
            "ANSI-X9.9",
            "ANSI-X9.19",
            "AS2805.4.1",
            "Retail-MAC-DES",
            "Retail-MAC-3DES"
    };

    /**
     * Generate MAC for data
     * 
     * @param data      Data to authenticate
     * @param key       MAC key (size depends on algorithm)
     * @param algorithm MAC algorithm
     * @return MAC value
     */
    public static byte[] generate(byte[] data, byte[] key, String algorithm) throws Exception {
        validateKeySize(key, algorithm);

        if (algorithm.startsWith("HMAC-")) {
            return generateHMAC(data, key, algorithm);
        } else if (algorithm.startsWith("CMAC-")) {
            return generateCMAC(data, key, algorithm);
        } else if (algorithm.startsWith("CBC-MAC-")) {
            return generateCBCMAC(data, key, algorithm);
        } else if (algorithm.equals("ISO-9797-1-ALG1")) {
            return generateISO9797Alg1(data, key);
        } else if (algorithm.equals("ANSI-X9.9")) {
            return generateANSIX99(data, key);
        } else if (algorithm.equals("ANSI-X9.19")) {
            return generateANSIX919(data, key);
        } else if (algorithm.equals("AS2805.4.1")) {
            return generateAS2805(data, key);
        } else if (algorithm.startsWith("Retail-MAC-")) {
            return generateRetailMAC(data, key, algorithm);
        } else {
            throw new IllegalArgumentException("Unknown MAC algorithm: " + algorithm);
        }
    }

    /**
     * Verify MAC value
     * 
     * @param data      Original data
     * @param mac       MAC value to verify
     * @param key       MAC key
     * @param algorithm MAC algorithm
     * @return true if MAC is valid
     */
    public static boolean verify(byte[] data, byte[] mac, byte[] key, String algorithm) throws Exception {
        byte[] computed = generate(data, key, algorithm);

        if (computed.length != mac.length) {
            return false;
        }

        // Constant-time comparison to prevent timing attacks
        int result = 0;
        for (int i = 0; i < computed.length; i++) {
            result |= computed[i] ^ mac[i];
        }

        return result == 0;
    }

    /**
     * Generate HMAC (Hash-based Message Authentication Code)
     */
    private static byte[] generateHMAC(byte[] data, byte[] key, String algorithm) throws Exception {
        String javaAlgorithm = algorithm; // "HMAC-SHA256" etc.

        javax.crypto.Mac mac = javax.crypto.Mac.getInstance(javaAlgorithm, "BC");
        SecretKeySpec keySpec = new SecretKeySpec(key, javaAlgorithm);
        mac.init(keySpec);

        return mac.doFinal(data);
    }

    /**
     * Generate CMAC (Cipher-based Message Authentication Code)
     * CMAC is based on a block cipher (AES or 3DES)
     */
    private static byte[] generateCMAC(byte[] data, byte[] key, String algorithm) throws Exception {
        BlockCipher cipher;

        if (algorithm.equals("CMAC-AES")) {
            cipher = new AESEngine();
        } else if (algorithm.equals("CMAC-3DES")) {
            cipher = new DESedeEngine();
        } else {
            throw new IllegalArgumentException("Unknown CMAC cipher: " + algorithm);
        }

        CMac cmac = new CMac(cipher);
        KeyParameter keyParam = new KeyParameter(key);
        cmac.init(keyParam);

        cmac.update(data, 0, data.length);

        byte[] output = new byte[cmac.getMacSize()];
        cmac.doFinal(output, 0);

        return output;
    }

    /**
     * Generate CBC-MAC (Cipher Block Chaining MAC)
     * CBC-MAC is the last block of CBC encryption
     */
    private static byte[] generateCBCMAC(byte[] data, byte[] key, String algorithm) throws Exception {
        BlockCipher cipher;

        if (algorithm.equals("CBC-MAC-DES")) {
            cipher = new DESEngine();
        } else if (algorithm.equals("CBC-MAC-3DES")) {
            cipher = new DESedeEngine();
        } else if (algorithm.equals("CBC-MAC-AES")) {
            cipher = new AESEngine();
        } else {
            throw new IllegalArgumentException("Unknown CBC-MAC cipher: " + algorithm);
        }

        CBCBlockCipherMac mac = new CBCBlockCipherMac(cipher);
        KeyParameter keyParam = new KeyParameter(key);
        mac.init(keyParam);

        mac.update(data, 0, data.length);

        byte[] output = new byte[mac.getMacSize()];
        mac.doFinal(output, 0);

        return output;
    }

    /**
     * Generate Retail MAC (ISO 9797-1 Algorithm 3)
     * Note: BP-Tools "Retail MAC" with "Finalize: None" is actually just CBC-MAC
     * For compatibility, we implement CBC-MAC here
     */
    private static byte[] generateRetailMAC(byte[] data, byte[] key, String algorithm) throws Exception {
        if (algorithm.equals("Retail-MAC-DES")) {
            return generateCBCMAC(data, key, "CBC-MAC-DES");
        } else if (algorithm.equals("Retail-MAC-3DES")) {
            // Retail MAC with 3DES (Alg 1)
            return generateCBCMAC(data, key, "CBC-MAC-3DES");
        } else {
            throw new IllegalArgumentException("Unknown Retail MAC cipher: " + algorithm);
        }
    }

    /**
     * Generate ANSI X9.9 MAC
     * Financial standard using DES CBC-MAC with ISO 9797-1 padding method 2 (0x80 +
     * 0x00...)
     * Used in financial messages, produces 8-byte MAC
     */
    private static byte[] generateANSIX99(byte[] data, byte[] key) throws Exception {
        // ANSI X9.9 uses DES in CBC mode with ISO 9797-1 padding method 2
        // This is essentially CBC-MAC-DES
        return generateCBCMAC(data, key, "CBC-MAC-DES");
    }

    /**
     * Generate ISO 9797-1 Algorithm 1 (DES only)
     * Standard CBC-MAC using DES
     * Padding: Method 1 (zero padding)
     */
    private static byte[] generateISO9797Alg1(byte[] data, byte[] key) throws Exception {
        // ISO 9797-1 Algorithm 1 with DES
        // Uses CBC-MAC (same as CBC-MAC-DES)
        return generateCBCMAC(data, key, "CBC-MAC-DES");
    }

    /**
     * Generate ANSI X9.19 MAC (Retail MAC - ISO 9797-1 Algorithm 3)
     * Financial standard using DES with encrypt-decrypt-encrypt on final block
     * Uses ISO9797Alg3Mac from BouncyCastle (Retail MAC)
     */
    private static byte[] generateANSIX919(byte[] data, byte[] key) throws Exception {
        // ANSI X9.19 uses ISO 9797-1 Algorithm 3 (Retail MAC)
        // Key format: K || K' (16 bytes total)

        if (key.length != 16 && key.length != 24) {
            throw new IllegalArgumentException("ANSI X9.19 requires 16-byte (2-key) or 24-byte (3-key) key");
        }

        // ISO9797Alg3Mac implements Retail MAC algorithm:
        // 1. CBC-MAC with DES using K
        // 2. Decrypt last block with K'
        // 3. Encrypt with K
        BlockCipher cipher = new DESEngine();
        ISO9797Alg3Mac mac = new ISO9797Alg3Mac(cipher);

        // Initialize with full key (K||K')
        KeyParameter keyParam = new KeyParameter(key);
        mac.init(keyParam);

        // Process data
        mac.update(data, 0, data.length);

        // Get MAC result
        byte[] output = new byte[mac.getMacSize()];
        mac.doFinal(output, 0);

        return output;
    }

    /**
     * Generate AS2805.4.1 MAC
     * Australian Standard for financial transactions
     * Same algorithm as ANSI X9.19
     */
    private static byte[] generateAS2805(byte[] data, byte[] key) throws Exception {
        // AS2805.4.1 uses same algorithm as ANSI X9.19
        return generateANSIX919(data, key);
    }

    /**
     * Validate key size for algorithm
     */
    private static void validateKeySize(byte[] key, String algorithm) {
        int keyBits = key.length * 8;

        if (algorithm.startsWith("HMAC-")) {
            // HMAC accepts any key size, but recommend at least hash size
            if (keyBits < 128) {
                throw new IllegalArgumentException("HMAC key should be at least 128 bits (16 bytes)");
            }
        } else if (algorithm.contains("AES")) {
            if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
                throw new IllegalArgumentException(
                        "AES key must be 128, 192, or 256 bits (16, 24, or 32 bytes). Got: " + keyBits + " bits");
            }
        } else if (algorithm.equals("ISO-9797-1-ALG1")) {
            // ISO 9797-1 Algorithm 1 with DES (standard only defines DES)
            if (keyBits != 64) {
                throw new IllegalArgumentException(
                        "ISO 9797-1 Algorithm 1 key must be 64 bits (8 bytes, DES). Got: " + keyBits + " bits");
            }
        } else if (algorithm.equals("ANSI-X9.9")) {
            // ANSI X9.9 uses DES (single key)
            if (keyBits != 64) {
                throw new IllegalArgumentException(
                        "ANSI X9.9 key must be 64 bits (8 bytes). Got: " + keyBits + " bits");
            }
        } else if (algorithm.equals("ANSI-X9.19")) {
            // ANSI X9.19 uses 3DES (2-key or 3-key)
            if (keyBits != 128 && keyBits != 192) {
                throw new IllegalArgumentException(
                        "ANSI X9.19 key must be 128 bits (16 bytes, 2-key) or 192 bits (24 bytes, 3-key). Got: "
                                + keyBits + " bits");
            }
        } else if (algorithm.equals("AS2805.4.1")) {
            // AS2805.4.1 uses 3DES (2-key or 3-key)
            if (keyBits != 128 && keyBits != 192) {
                throw new IllegalArgumentException(
                        "AS2805.4.1 key must be 128 bits (16 bytes, 2-key) or 192 bits (24 bytes, 3-key). Got: "
                                + keyBits + " bits");
            }
        } else if (algorithm.equals("Retail-MAC-DES")) {
            // Retail-MAC-DES uses CBC-MAC-DES internally
            if (keyBits != 64) {
                throw new IllegalArgumentException(
                        "Retail-MAC-DES key must be 64 bits (8 bytes). Got: " + keyBits + " bits");
            }
        } else if (algorithm.equals("Retail-MAC-3DES")) {
            // Retail-MAC-3DES uses CBC-MAC-3DES internally
            if (keyBits != 128 && keyBits != 192) {
                throw new IllegalArgumentException(
                        "Retail-MAC-3DES key must be 128 bits (16 bytes, 2-key) or 192 bits (24 bytes, 3-key). Got: "
                                + keyBits + " bits");
            }
        } else if (algorithm.contains("3DES")) {
            if (keyBits != 128 && keyBits != 192) {
                throw new IllegalArgumentException(
                        "3DES key must be 128 bits (16 bytes, 2-key) or 192 bits (24 bytes, 3-key). Got: " + keyBits
                                + " bits");
            }
        } else if (algorithm.contains("DES") && !algorithm.contains("3DES")) {
            if (keyBits != 64) {
                throw new IllegalArgumentException("DES key must be 64 bits (8 bytes). Got: " + keyBits + " bits");
            }
        }
    }

    /**
     * Get algorithm information
     */
    public static String getAlgorithmInfo(String algorithm) {
        switch (algorithm) {
            // HMAC
            case "HMAC-SHA1":
                return "HMAC-SHA1 - Hash-based MAC with SHA-1 (legacy, 160-bit)";
            case "HMAC-SHA256":
                return "HMAC-SHA256 - Hash-based MAC with SHA-256 (256-bit, recommended)";
            case "HMAC-SHA384":
                return "HMAC-SHA384 - Hash-based MAC with SHA-384 (384-bit)";
            case "HMAC-SHA512":
                return "HMAC-SHA512 - Hash-based MAC with SHA-512 (512-bit)";

            // CMAC
            case "CMAC-AES":
                return "CMAC-AES - Cipher-based MAC with AES (128-bit output)";
            case "CMAC-3DES":
                return "CMAC-3DES - Cipher-based MAC with 3DES (64-bit output)";

            // CBC-MAC
            case "CBC-MAC-DES":
                return "CBC-MAC-DES - CBC mode MAC with DES (64-bit output)";
            case "CBC-MAC-3DES":
                return "CBC-MAC-3DES - CBC mode MAC with 3DES (64-bit output)";
            case "CBC-MAC-AES":
                return "CBC-MAC-AES - CBC mode MAC with AES (128-bit output)";

            // ISO 9797-1 Standards
            case "ISO-9797-1-ALG1":
                return "ISO 9797-1 Algorithm 1 - Standard CBC-MAC with DES (8-byte output, zero padding)";

            // ANSI Standards
            case "ANSI-X9.9":
                return "ANSI X9.9 - Financial MAC standard using DES CBC-MAC (8-byte output, banking)";
            case "ANSI-X9.19":
                return "ANSI X9.19 - Financial MAC standard using 3DES (8-byte output, banking)";
            case "AS2805.4.1":
                return "AS2805.4.1 - Australian Standard for financial transactions using 3DES (8-byte output)";

            // Retail MAC
            case "Retail-MAC-DES":
                return "Retail-MAC-DES - CBC-MAC with DES (BP-Tools compatible, banking standard)";
            case "Retail-MAC-3DES":
                return "Retail-MAC-3DES - CBC-MAC with 3DES (BP-Tools compatible, banking standard). Note: This is CBC-MAC, not ISO 9797-1 Algorithm 3 with decrypt/encrypt steps.";

            default:
                return "Unknown algorithm";
        }
    }

    /**
     * Get expected key size for algorithm
     */
    public static String getExpectedKeySize(String algorithm) {
        if (algorithm.startsWith("HMAC-")) {
            return "≥16 bytes (any size, recommend ≥hash size)";
        } else if (algorithm.contains("AES")) {
            return "16, 24, or 32 bytes (128, 192, or 256 bits)";
        } else if (algorithm.equals("ISO-9797-1-ALG1")) {
            return "8 bytes (64 bits, DES)";
        } else if (algorithm.equals("ANSI-X9.9")) {
            return "8 bytes (64 bits)";
        } else if (algorithm.equals("ANSI-X9.19")) {
            return "16 or 24 bytes (2-key or 3-key 3DES)";
        } else if (algorithm.equals("AS2805.4.1")) {
            return "16 or 24 bytes (2-key or 3-key 3DES)";
        } else if (algorithm.equals("Retail-MAC-DES")) {
            return "8 bytes (64 bits)";
        } else if (algorithm.equals("Retail-MAC-3DES")) {
            return "16 or 24 bytes (2-key or 3-key 3DES)";
        } else if (algorithm.contains("3DES")) {
            return "16 or 24 bytes (2-key or 3-key 3DES)";
        } else if (algorithm.contains("DES") && !algorithm.contains("3DES")) {
            return "8 bytes (64 bits)";
        }
        return "Unknown";
    }
}
