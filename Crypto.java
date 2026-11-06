package ee.taltech.secprog.pm;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * All cryptography lives in this one file so it can be reviewed in one place.
 * PBKDF2 turns the master password into an AES-256 key; AES-GCM encrypts the vault.
 */
final class Crypto {
    static final int SALT_LENGTH = 16;      // bytes
    static final int IV_LENGTH = 12;        // bytes; 96 bits is the standard GCM nonce size
    static final int KEY_BITS = 256;
    static final int GCM_TAG_BITS = 128;
    static final int PBKDF2_ITERATIONS = 600_000;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Crypto() {}

    static byte[] randomBytes(int length) {
        byte[] b = new byte[length];
        RANDOM.nextBytes(b);
        return b;
    }

    static SecretKey deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] raw = factory.generateSecret(spec).getEncoded();
            try {
                return new SecretKeySpec(raw, "AES"); // SecretKeySpec copies the array
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
        } finally {
            spec.clearPassword(); // PBEKeySpec keeps its own copy of the password; wipe it
        }
    }

    /** Returns IV || ciphertext || tag. A new random IV is generated on every call. */
    static byte[] encrypt(SecretKey key, byte[] plaintext) throws GeneralSecurityException {
        byte[] iv = randomBytes(IV_LENGTH);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = cipher.doFinal(plaintext);
        byte[] out = new byte[IV_LENGTH + ct.length];
        System.arraycopy(iv, 0, out, 0, IV_LENGTH);
        System.arraycopy(ct, 0, out, IV_LENGTH, ct.length);
        return out;
    }

    /** Input is IV || ciphertext || tag. Throws AEADBadTagException on a wrong key or tampered data. */
    static byte[] decrypt(SecretKey key, byte[] ivAndCiphertext) throws GeneralSecurityException {
        if (ivAndCiphertext.length < IV_LENGTH + GCM_TAG_BITS / 8) {
            throw new GeneralSecurityException("Vault data is too short");
        }
        byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, IV_LENGTH);
        byte[] ct = Arrays.copyOfRange(ivAndCiphertext, IV_LENGTH, ivAndCiphertext.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(ct);
    }
}
