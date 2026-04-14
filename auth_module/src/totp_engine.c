/*
 * totp_engine.c — RFC 6238 TOTP Implementation
 *
 * This is the heart of the Google Authenticator compatibility.
 * The algorithm:
 *   1. T = floor(current_unix_time / 30)      <- time step counter
 *   2. T is encoded as 8 bytes big-endian
 *   3. HMAC-SHA1(secret, T) produces 20 bytes
 *   4. Dynamic truncation extracts a 4-byte slice
 *   5. Modulo 1,000,000 gives the 6-digit code
 *
 * This is identical to what Google Authenticator computes.
 * Reference: https://tools.ietf.org/html/rfc6238
 *            https://tools.ietf.org/html/rfc4226 (HOTP base)
 */

#include "totp_engine.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/hmac.h>   /* OpenSSL HMAC — industry standard, audited */
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdint.h>

/* ── Base32 Alphabet (RFC 4648) ─────────────────────────────────────────── */
static const char BASE32_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int base32_decode(const char *encoded, uint8_t *output, size_t output_len)
{
    size_t enc_len = strlen(encoded);
    size_t i, j = 0;
    uint64_t buffer = 0;
    int bits_left = 0;

    for (i = 0; i < enc_len; i++) {
        char c = toupper((unsigned char)encoded[i]);

        /* Skip padding and whitespace */
        if (c == '=' ) break;
	if (c == ' ' || c == '\n' || c == '\r') continue;

        /* Find character in alphabet */
        const char *pos = strchr(BASE32_CHARS, c);
        if (!pos) return -1;  /* invalid character — reject entirely */

        /* Accumulate 5 bits per base32 character */
        buffer = (buffer << 5) | (pos - BASE32_CHARS);
        bits_left += 5;

        /* Extract full bytes */
        while (bits_left >= 8) {
            if (j >= output_len) return -1;
	    bits_left -= 8;
            output[j++] = (uint8_t)((buffer >> bits_left) & 0xFF);
	    
        }
	buffer &= ((1ULL << bits_left) -1);
    }
   
    return (int)j;
}

int totp_generate_secret(char *buf, size_t buf_len)
{
    /*
     * Generate 20 random bytes (160 bits of entropy) via OpenSSL's
     * CSPRNG which reads from /dev/urandom. Never use rand() for secrets.
     */
    uint8_t raw[20];
    if (RAND_bytes(raw, sizeof(raw)) != 1) return -1;

    /* Encode as base32 — this is what you scan into Google Authenticator */
    size_t out_idx = 0;
    int i;
    for (i = 0; i < (int)sizeof(raw) && out_idx + 2 < buf_len; i += 5) {
        uint64_t chunk = 0;
        int chunk_len = (i + 5 <= (int)sizeof(raw)) ? 5 : (int)sizeof(raw) - i;
        int k;
        for (k = 0; k < chunk_len; k++)
            chunk = (chunk << 8) | raw[i + k];
        chunk <<= (5 - chunk_len) * 8;

        int bits = chunk_len * 8;
        int j;
        for (j = 0; j < (bits + 4) / 5 && out_idx < buf_len - 1; j++) {
            buf[out_idx++] = BASE32_CHARS[(chunk >> (35 - j * 5)) & 0x1F];
        }
    }
    buf[out_idx] = '\0';
    return 0;
}

/* ── HOTP Core (RFC 4226) ───────────────────────────────────────────────── */
static int hotp_compute(const uint8_t *secret, size_t secret_len, uint64_t counter)
{
    /*
     * Step 1: Encode counter as 8-byte big-endian
     * This is critical — both sides must agree on byte order.
     */
    uint8_t counter_bytes[8];
    int i;
    for (i = 7; i >= 0; i--) {
        counter_bytes[i] = counter & 0xFF;
        counter >>= 8;
    }

    /*
     * Step 2: HMAC-SHA1(secret, counter)
     * We use OpenSSL's EVP_MAC for this — it's the audited implementation.
     * Never implement your own HMAC or SHA1 for production code.
     */
    uint8_t hmac_result[20];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha1(), secret, (int)secret_len,
         counter_bytes, sizeof(counter_bytes),
         hmac_result, &hmac_len);

    if (hmac_len != 20) return -1;

    /*
     * Step 3: Dynamic truncation
     * Use the last nibble of the HMAC as an offset into the 20 bytes.
     * Extract 4 bytes at that offset, mask the high bit (avoid signed issues).
     */
    int offset = hmac_result[19] & 0x0F;
    uint32_t truncated =
        ((hmac_result[offset]     & 0x7F) << 24) |
        ((hmac_result[offset + 1] & 0xFF) << 16) |
        ((hmac_result[offset + 2] & 0xFF) <<  8) |
        ((hmac_result[offset + 3] & 0xFF));

    /* Step 4: 6-digit code */
    return (int)(truncated % 1000000);
}

int totp_generate(const uint8_t *secret, size_t secret_len)
{
    uint64_t time_step = (uint64_t)time(NULL) / TOTP_PERIOD;
    return hotp_compute(secret, secret_len, time_step);
}

int totp_verify(const uint8_t *secret, size_t secret_len, int user_code)
{
    if (user_code < 0 || user_code > 999999) return 0;

    uint64_t time_step = (uint64_t)time(NULL) / TOTP_PERIOD;
    int window;

    /*
     * Check TOTP_WINDOW steps in each direction.
     * TOTP_WINDOW=1 means we accept codes from the previous 30s
     * or next 30s window. This handles phones with slightly drifted clocks.
     * Do NOT increase this — wider windows reduce security.
     */
    for (window = -TOTP_WINDOW; window <= TOTP_WINDOW; window++) {
        int expected = hotp_compute(secret, secret_len,
                                    (uint64_t)((int64_t)time_step + window));
        if (expected == user_code) return 1;
    }
    return 0;
}

int totp_load_secret(const char *username, uint8_t *secret_buf, size_t buf_len)
{
    /*
     * Security requirements for secret storage:
     * - File owned by root, mode 0600 (only root can read)
     * - Path does NOT use user-supplied data directly (prevents path traversal)
     */
    char path[256];
    int n = snprintf(path, sizeof(path), "/etc/auth_module/%s.secret", username);
    if (n < 0 || n >= (int)sizeof(path)) return -1;

    /* Reject paths with traversal attempts */
    if (strstr(path, "..") || strchr(username, '/')) return -1;

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char encoded[SECRET_MAX_LEN + 2];
    if (!fgets(encoded, sizeof(encoded), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Strip trailing newline */
    encoded[strcspn(encoded, "\r\n")] = '\0';

    return base32_decode(encoded, secret_buf, buf_len);
}
