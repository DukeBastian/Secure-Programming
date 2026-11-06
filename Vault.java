package ee.taltech.secprog.pm;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Encrypted vault on disk: salt (16 bytes, public) || IV (12) || ciphertext || GCM tag.
 * The key is derived from the master password and kept in memory only while unlocked.
 */
final class Vault {

    static final class WrongPasswordException extends Exception {
        WrongPasswordException() {
            super("Wrong master password, or the vault file is damaged.");
        }
    }

    private final Path file;
    private final byte[] salt;
    private final SecretKey key;
    private final Map<String, Credential> entries = new TreeMap<>();

    private Vault(Path file, byte[] salt, SecretKey key) {
        this.file = file;
        this.salt = salt;
        this.key = key;
    }

    /** Creates a new vault if the file does not exist; otherwise unlocks the existing one. */
    static Vault open(Path file, char[] masterPassword)
            throws IOException, GeneralSecurityException, WrongPasswordException {
        if (!Files.exists(file)) {
            Validator.requireMasterPassword(masterPassword);
            byte[] salt = Crypto.randomBytes(Crypto.SALT_LENGTH);
            Vault vault = new Vault(file, salt, Crypto.deriveKey(masterPassword, salt));
            vault.save();
            return vault;
        }

        byte[] data = Files.readAllBytes(file);
        if (data.length <= Crypto.SALT_LENGTH) {
            throw new IOException("Vault file is too short to be valid.");
        }
        byte[] salt = Arrays.copyOfRange(data, 0, Crypto.SALT_LENGTH);
        byte[] sealed = Arrays.copyOfRange(data, Crypto.SALT_LENGTH, data.length);

        SecretKey key = Crypto.deriveKey(masterPassword, salt);
        byte[] plain;
        try {
            // This is the verification step: GCM checks the tag. A wrong key fails here,
            // so no plaintext is ever returned for an incorrect password.
            plain = Crypto.decrypt(key, sealed);
        } catch (AEADBadTagException e) {
            throw new WrongPasswordException();
        }

        Vault vault = new Vault(file, salt, key);
        try {
            vault.parse(plain);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
        return vault;
    }

    List<String> services() {
        return new ArrayList<>(entries.keySet());
    }

    Credential get(String service) {
        return entries.get(service);
    }

    void put(Credential credential) {
        entries.put(credential.service(), credential);
    }

    boolean remove(String service) {
        return entries.remove(service) != null;
    }

    /** Encrypts the whole vault and replaces the file atomically. */
    void save() throws IOException, GeneralSecurityException {
        byte[] plain = serialize();
        byte[] sealed;
        try {
            sealed = Crypto.encrypt(key, plain);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }

        byte[] out = new byte[salt.length + sealed.length];
        System.arraycopy(salt, 0, out, 0, salt.length);
        System.arraycopy(sealed, 0, out, salt.length, sealed.length);

        // Write a temp file, then swap it in, so a crash never leaves a half-written vault.
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        Files.write(tmp, out);
        Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE);
    }

    /** Forgets the decrypted entries. The caller must also drop the Vault object. */
    void lock() {
        entries.clear();
    }

    private byte[] serialize() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(entries.size());
            for (Credential c : entries.values()) {
                out.writeUTF(c.service());
                out.writeUTF(c.username());
                out.writeUTF(c.password());
            }
        }
        return bytes.toByteArray();
    }

    private void parse(byte[] plain) throws IOException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(plain))) {
            int count = in.readInt();
            for (int i = 0; i < count; i++) {
                put(new Credential(in.readUTF(), in.readUTF(), in.readUTF()));
            }
        }
    }
}
