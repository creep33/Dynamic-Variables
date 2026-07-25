package burp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TotpGeneratorTest {
    // RFC 6238 Appendix B test keys.
    private static final byte[] SHA1_KEY =
            "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SHA256_KEY =
            "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SHA512_KEY =
            "1234567890123456789012345678901234567890123456789012345678901234"
                    .getBytes(StandardCharsets.US_ASCII);

    @Test
    void matchesTheRfc6238TestVectors() {
        assertEquals("94287082", TotpGenerator.code(SHA1_KEY, 59L, 8, 30, "SHA1"));
        assertEquals("46119246", TotpGenerator.code(SHA256_KEY, 59L, 8, 30, "SHA256"));
        assertEquals("90693936", TotpGenerator.code(SHA512_KEY, 59L, 8, 30, "SHA512"));

        assertEquals("07081804", TotpGenerator.code(SHA1_KEY, 1111111109L, 8, 30, "SHA1"));
        assertEquals("14050471", TotpGenerator.code(SHA1_KEY, 1111111111L, 8, 30, "SHA1"));
        assertEquals("89005924", TotpGenerator.code(SHA1_KEY, 1234567890L, 8, 30, "SHA1"));
        assertEquals("69279037", TotpGenerator.code(SHA1_KEY, 2000000000L, 8, 30, "SHA1"));
        assertEquals("65353130", TotpGenerator.code(SHA1_KEY, 20000000000L, 8, 30, "SHA1"));

        assertEquals("68084774", TotpGenerator.code(SHA256_KEY, 1111111109L, 8, 30, "SHA256"));
        assertEquals("25091201", TotpGenerator.code(SHA512_KEY, 1111111109L, 8, 30, "SHA512"));
    }

    @Test
    void sixDigitCodesAreTheLowOrderDigitsOfTheEightDigitOnes() {
        assertEquals("287082", TotpGenerator.code(SHA1_KEY, 59L, 6, 30, "SHA1"));
        assertEquals("081804", TotpGenerator.code(SHA1_KEY, 1111111109L, 6, 30, "SHA1"));
    }

    @Test
    void decodesTheBase32SecretFromTheConfiguration() {
        // Base32 of the RFC 6238 SHA1 key, the format an authenticator app shows.
        TotpGenerator.TotpConfig config = new TotpGenerator.TotpConfig(
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 8, 30, "SHA1");

        assertEquals("94287082", TotpGenerator.code(config, 59L));
        assertEquals("14050471", TotpGenerator.code(config, 1111111111L));
    }

    @Test
    void base32DecodingFollowsRfc4648AndToleratesUserFormatting() {
        assertArrayEquals("f".getBytes(StandardCharsets.US_ASCII), TotpGenerator.decodeBase32("MY======"));
        assertArrayEquals("fo".getBytes(StandardCharsets.US_ASCII), TotpGenerator.decodeBase32("MZXQ===="));
        assertArrayEquals("foo".getBytes(StandardCharsets.US_ASCII), TotpGenerator.decodeBase32("MZXW6==="));
        assertArrayEquals("foob".getBytes(StandardCharsets.US_ASCII), TotpGenerator.decodeBase32("MZXW6YQ="));
        assertArrayEquals("fooba".getBytes(StandardCharsets.US_ASCII), TotpGenerator.decodeBase32("MZXW6YTB"));
        assertArrayEquals("foobar".getBytes(StandardCharsets.US_ASCII), TotpGenerator.decodeBase32("MZXW6YTBOI======"));

        // Lowercase, spaces and dashes are what users actually paste.
        assertArrayEquals(TotpGenerator.decodeBase32("MZXW6YTBOI"),
                TotpGenerator.decodeBase32("mzxw 6ytb-oi"));
    }

    @Test
    void rejectsSecretsThatAreNotBase32() {
        assertThrows(IllegalArgumentException.class, () -> TotpGenerator.decodeBase32("!!!!"));
        assertThrows(IllegalArgumentException.class, () -> TotpGenerator.decodeBase32("ABC1"));
        assertThrows(IllegalArgumentException.class, () -> TotpGenerator.decodeBase32(""));
        assertThrows(IllegalArgumentException.class,
                () -> TotpGenerator.code(TotpGenerator.TotpConfig.empty(), 59L));
    }

    @Test
    void reportsTheTimeStepAndTheSecondsLeftInIt() {
        assertEquals(1L, TotpGenerator.timeStep(59L, 30));
        assertEquals(2L, TotpGenerator.timeStep(60L, 30));
        assertEquals(1L, TotpGenerator.secondsRemaining(59L, 30));
        assertEquals(30, TotpGenerator.secondsRemaining(60L, 30));
        assertEquals(15, TotpGenerator.secondsRemaining(45L, 30));
    }

    @Test
    void configurationFallsBackToTheStandardDefaults() {
        TotpGenerator.TotpConfig config = new TotpGenerator.TotpConfig("  gezdgnbv  ", 0, 0, null);

        assertEquals("GEZDGNBV", config.secret().toUpperCase(java.util.Locale.ROOT));
        assertEquals(6, config.digits());
        assertEquals(30, config.periodSeconds());
        assertEquals("SHA1", config.algorithm());
    }
}
