import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Disclaimer: This code is for illustration purposes.
 * Do not use in real-world deployments.
 */

public class AESDemo {

    public static int AES_KEY_LENGTH = 16; // in bytes
    public static int BLOCK_LENGTH = 16; // in bytes
    private static SecureRandom rnd = new SecureRandom();

    /**
     * This method encrypts a message using the AES block cipher. It uses the
     * CBC-mode and PKCS#5 PADDING as discussed in lecture. It returns a byte array
     * containing the IV and other ciphertext blocks.
     */
    public static byte[] encrypt(byte[] key, String message) {
        if (key.length != AES_KEY_LENGTH) {
            throw new IllegalArgumentException("Unexpected key or iv length!");
        }
        try {
            byte[] iv = ivRandGen();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
            byte[] encrypted = cipher.doFinal(message.getBytes());
            return prepareCiphertext(iv, encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * This method decrypts a ciphertext given the key. The ciphertext array is
     * assumed to contain the IV.
     */

    public static byte[] decrypt(byte[] key, byte[] ciphertext) {

        byte[] iv = extractIV(ciphertext);
        byte[] ciphertextBlocks = extractCiphertextBlocks(ciphertext);
        if (key.length != AES_KEY_LENGTH || iv.length != BLOCK_LENGTH) {
            throw new IllegalArgumentException("Unexpected key or iv length!");
        }
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
            byte[] decrypted = cipher.doFinal(ciphertextBlocks);
            return decrypted;
        } catch (Exception e) {
            // e.printStackTrace();
        }
        return null;
    }

    /**
     * This method generates the secret key
     */
    public static byte[] keyGen() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_LENGTH * 8); // in bits
            SecretKey secretKey = keyGen.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] ivRandGen() {
        byte[] iv = new byte[BLOCK_LENGTH];
        rnd.nextBytes(iv);
        return iv;
    }

    /**
     * Utility method
     */
    public static String toHex(byte[] a) {
        StringBuilder stringBuilder = new StringBuilder(a.length * 2);
        for (byte b : a)
            stringBuilder.append(String.format("%02x", b));
        return stringBuilder.toString();
    }

    /**
     * Utility method: Extracts the IV from the ciphertext array
     */
    public static byte[] extractIV(byte[] ciphertext) {
        return Arrays.copyOfRange(ciphertext, 0, BLOCK_LENGTH);
    }

    /**
     * Utility method: Extracts the rest of the ciphertext blocks from the
     * ciphertext array
     */
    public static byte[] extractCiphertextBlocks(byte[] ciphertext) {
        return Arrays.copyOfRange(ciphertext, BLOCK_LENGTH, ciphertext.length);
    }

    /**
     * Utility method: combines the iv and ciphertext blocks in one array
     */
    public static byte[] prepareCiphertext(byte[] iv, byte[] ciphertextBlocks) {
        byte[] combined = new byte[iv.length + ciphertextBlocks.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertextBlocks, 0, combined, iv.length, ciphertextBlocks.length);
        return combined;

    }

    public static void main(String[] args) {

        byte[] key = keyGen();
        String message = "Hello World!";
        byte[] ciphertext = encrypt(key, message);
        ciphertext[ciphertext.length - 1] = 10;
        String decipheredMessage = new String(decrypt(key, ciphertext));

        System.out.println("Message before encryption: " + message);
        System.out.println("Encrypted message: \nIV: " + toHex(extractIV(ciphertext)) + "\nCiphertext Blocks: "
                + toHex(extractCiphertextBlocks(ciphertext)));
        System.out.println("Message after decryption: " + decipheredMessage);

        if (!decipheredMessage.equals(message)) {
            System.err.println("The decryption result does not match the original plaintext");
        }
    }
}