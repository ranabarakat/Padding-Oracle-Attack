import java.util.Random;

/**
 * Disclaimer:
 * This code is for illustration purposes.
 * Do not use in real-world deployments.
 */

public class PaddingOracleAttackSimulation {

    private static class Sender {
        private byte[] secretKey;
        private String secretMessage = "Top secret!"; // 11 bytes 5 padding

        public Sender(byte[] secretKey) {
            this.secretKey = secretKey;
        }

        // This will return both iv and ciphertext
        public byte[] encrypt() {
            return AESDemo.encrypt(secretKey, secretMessage);
        }
    }

    private static class Receiver {
        private byte[] secretKey;

        public Receiver(byte[] secretKey) {
            this.secretKey = secretKey;
        }

        // Padding Oracle (Notice the return type)
        public boolean isDecryptionSuccessful(byte[] ciphertext) {
            return AESDemo.decrypt(secretKey, ciphertext) != null;
        }
    }

    public static class Adversary {

        // This is where you are going to develop the attack
        // Assume you cannot access the key.
        // You shall not add any methods to the Receiver class.
        // You only have access to the receiver's "isDecryptionSuccessful" only.
        public String extractSecretMessage(Receiver receiver, byte[] ciphertext) {

            byte[] iv = AESDemo.extractIV(ciphertext);
            byte[] ciphertextBlocks = AESDemo.extractCiphertextBlocks(ciphertext);
            boolean result = receiver.isDecryptionSuccessful(AESDemo.prepareCiphertext(iv, ciphertextBlocks));
            System.out.println(result); // This is true initially, as the ciphertext was not altered in any way.

            // TODO: WRITE THE ATTACK HERE.
            int i = -1;
            Random random = new Random();
            byte[] ivCpy = iv.clone();
            for (i = 1; i <= AESDemo.BLOCK_LENGTH; i++) {
                ivCpy[i - 1] = (byte) (random.nextInt(256) - ivCpy[i - 1]);
                result = receiver.isDecryptionSuccessful(AESDemo.prepareCiphertext(ivCpy, ciphertextBlocks));
                if (!result)
                    break;
            }
            i--;
            byte[] secretMsg = new byte[i];
            byte padding = (byte) (AESDemo.BLOCK_LENGTH - i);
            byte[] fk = new byte[AESDemo.BLOCK_LENGTH];
            System.arraycopy(iv, 0, fk, 0, iv.length);
            for (int j = fk.length - padding; j < fk.length; j++) {
                fk[j] = (byte) (iv[j] ^ padding);
            }
            int pad = 0;
            for (int m = AESDemo.BLOCK_LENGTH - (padding + 1); m >= 0; m--) {
                pad = AESDemo.BLOCK_LENGTH - m;
                ivCpy = prepareIv(ivCpy, fk, pad);
                for (byte k = -128; k <= 127; k++) {
                    ivCpy[m] = k;
                    if (receiver.isDecryptionSuccessful(AESDemo.prepareCiphertext(ivCpy, ciphertextBlocks))) {
                        // System.out.println("FOUND");
                        fk[m] = (byte) (ivCpy[m] ^ pad);
                        secretMsg[m] = (byte) (fk[m] ^ iv[m]);
                        break;
                    }
                }
            }
            return new String(secretMsg);
        }

        byte[] prepareIv(byte[] ivv, byte[] fk, int pad) {
            for (int i = AESDemo.BLOCK_LENGTH - 1; i > AESDemo.BLOCK_LENGTH - 1 - pad; i--) {
                ivv[i] = (byte) (fk[i] ^ pad);
            }
            return ivv;
        }
    }

    public static void main(String[] args) {

        byte[] secretKey = AESDemo.keyGen();
        Sender sender = new Sender(secretKey);
        Receiver receiver = new Receiver(secretKey);

        // The adversary does not have the key
        Adversary adversary = new Adversary();

        // Now, let's get some valid encryption from the sender
        byte[] ciphertext = sender.encrypt();

        // The adversary got the encrypted message from the network.
        // The adversary's goal is to extract the message without knowing the key.
        String message = adversary.extractSecretMessage(receiver, ciphertext);

        System.out.println("Extracted message = " + message);
    }
}