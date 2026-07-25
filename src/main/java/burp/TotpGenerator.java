package burp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Locale;

/**
 * RFC 6238 (TOTP) over RFC 4226 (HOTP). Pure functions of secret and time: no state,
 * no timers, no Montoya. The caller decides when a code is needed.
 */
final class TotpGenerator {
    static final int DEFAULT_DIGITS = 6;
    static final int DEFAULT_PERIOD_SECONDS = 30;
    static final String DEFAULT_ALGORITHM = "SHA1";

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int[] POWERS_OF_TEN = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

    record TotpConfig(String secret, int digits, int periodSeconds, String algorithm) {
        TotpConfig {
            secret = secret == null ? "" : secret.trim();
            digits = digits <= 0 ? DEFAULT_DIGITS : digits;
            periodSeconds = periodSeconds <= 0 ? DEFAULT_PERIOD_SECONDS : periodSeconds;
            algorithm = algorithm == null || algorithm.isBlank()
                    ? DEFAULT_ALGORITHM
                    : algorithm.trim().toUpperCase(Locale.ROOT);
        }

        static TotpConfig empty() {
            return new TotpConfig("", DEFAULT_DIGITS, DEFAULT_PERIOD_SECONDS, DEFAULT_ALGORITHM);
        }

        boolean isConfigured() {
            return !secret.isEmpty();
        }
    }

    private TotpGenerator() {}

    /** RFC 4648 base32, case-insensitive, ignoring spaces, dashes and padding. */
    static byte[] decodeBase32(String secret) {
        if (secret == null) throw new IllegalArgumentException("Secret is empty");
        StringBuilder normalized = new StringBuilder();
        for (char character : secret.toUpperCase(Locale.ROOT).toCharArray()) {
            if (character == ' ' || character == '-' || character == '=' || character == '\t') continue;
            if (BASE32_ALPHABET.indexOf(character) < 0) {
                throw new IllegalArgumentException("Invalid base32 character: " + character);
            }
            normalized.append(character);
        }
        if (normalized.length() == 0) throw new IllegalArgumentException("Secret is empty");

        byte[] decoded = new byte[normalized.length() * 5 / 8];
        int buffer = 0;
        int bitsInBuffer = 0;
        int written = 0;
        for (int index = 0; index < normalized.length(); index++) {
            buffer = (buffer << 5) | BASE32_ALPHABET.indexOf(normalized.charAt(index));
            bitsInBuffer += 5;
            if (bitsInBuffer >= 8) {
                bitsInBuffer -= 8;
                decoded[written++] = (byte) (buffer >>> bitsInBuffer);
            }
        }
        return decoded;
    }

    static long timeStep(long epochSeconds, int periodSeconds) {
        int period = periodSeconds <= 0 ? DEFAULT_PERIOD_SECONDS : periodSeconds;
        return Math.floorDiv(epochSeconds, period);
    }

    static int secondsRemaining(long epochSeconds, int periodSeconds) {
        int period = periodSeconds <= 0 ? DEFAULT_PERIOD_SECONDS : periodSeconds;
        return (int) (period - Math.floorMod(epochSeconds, period));
    }

    static String code(TotpConfig config, long epochSeconds) {
        if (config == null || !config.isConfigured()) {
            throw new IllegalArgumentException("No 2FA secret configured");
        }
        return code(decodeBase32(config.secret()), epochSeconds,
                config.digits(), config.periodSeconds(), config.algorithm());
    }

    static String code(byte[] key, long epochSeconds, int digits, int periodSeconds, String algorithm) {
        if (key == null || key.length == 0) throw new IllegalArgumentException("Secret is empty");
        if (digits < 1 || digits > 8) throw new IllegalArgumentException("Digits must be between 1 and 8");

        byte[] counter = ByteBuffer.allocate(Long.BYTES).putLong(timeStep(epochSeconds, periodSeconds)).array();
        byte[] hash = hmac(key, counter, algorithm);

        // RFC 4226 dynamic truncation.
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);
        return String.format("%0" + digits + "d", binary % POWERS_OF_TEN[digits]);
    }

    private static byte[] hmac(byte[] key, byte[] message, String algorithm) {
        String macAlgorithm = switch (algorithm == null ? "" : algorithm.toUpperCase(Locale.ROOT)) {
            case "SHA256", "SHA-256" -> "HmacSHA256";
            case "SHA512", "SHA-512" -> "HmacSHA512";
            case "", "SHA1", "SHA-1" -> "HmacSHA1";
            default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        };
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(new SecretKeySpec(key, macAlgorithm));
            return mac.doFinal(message);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalArgumentException("Cannot compute " + macAlgorithm + ": " + e.getMessage(), e);
        }
    }
}
