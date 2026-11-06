package ee.taltech.secprog.pm;

import java.nio.CharBuffer;
import java.util.regex.Pattern;

/** Allow-list validation: accept only what we expect and reject everything else. */
final class Validator {
    static final int MASTER_MIN = 12;
    static final int MASTER_MAX = 128;
    static final int SECRET_MAX = 256;
    private static final Pattern NAME = Pattern.compile("[\\p{L}\\p{N} ._@+-]{1,100}");

    private Validator() {}

    static void requireMasterPassword(char[] pw) {
        if (pw == null || pw.length < MASTER_MIN || pw.length > MASTER_MAX) {
            throw new IllegalArgumentException(
                "Master password must be " + MASTER_MIN + " to " + MASTER_MAX + " characters.");
        }
        if (hasControlChars(CharBuffer.wrap(pw))) {
            throw new IllegalArgumentException("Master password contains control characters.");
        }
    }

    static String requireName(String value, String label) {
        if (value == null || !NAME.matcher(value.trim()).matches()) {
            throw new IllegalArgumentException(label
                + " may contain only letters, digits, spaces and . _ @ + - (max 100 characters).");
        }
        return value.trim();
    }

    static String requireSecret(String value) {
        if (value == null || value.isEmpty() || value.length() > SECRET_MAX || hasControlChars(value)) {
            throw new IllegalArgumentException(
                "Password must be 1 to " + SECRET_MAX + " characters with no control characters.");
        }
        return value;
    }

    private static boolean hasControlChars(CharSequence s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isISOControl(s.charAt(i))) {
                return true;
            }
        }
        return false;
    }
}
