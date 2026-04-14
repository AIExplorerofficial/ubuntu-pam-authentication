#ifndef TOTP_ENGINE_H
#define TOTP_ENGINE_H

#include <stdint.h>
#include <stddef.h>

/*
 * TOTP Engine — RFC 6238 compliant
 * Compatible with Google Authenticator, Authy, Microsoft Authenticator.
 *
 * How it works:
 *   1. A shared secret (base32-encoded) is stored per user.
 *   2. Every 30 seconds, both the server AND the authenticator app
 *      compute: HOTP(secret, floor(unix_time / 30))
 *   3. If the 6-digit codes match, the user is authenticated.
 *
 * No network calls. No Google servers. Purely mathematical.
 */

#define TOTP_DIGITS        6
#define TOTP_PERIOD        30      /* seconds per window */
#define TOTP_WINDOW        1       /* allow ±1 window for clock skew */
#define SECRET_MAX_LEN     64      /* max base32 secret length */
#define SECRET_FILE_MODE   0600    /* owner read/write only */

/*
 * Generate a TOTP code for the current time.
 * Returns the 6-digit code, or -1 on error.
 */
int totp_generate(const uint8_t *secret, size_t secret_len);

/*
 * Verify a user-supplied code against current time (with window tolerance).
 * Returns 1 if valid, 0 if invalid.
 */
int totp_verify(const uint8_t *secret, size_t secret_len, int user_code);

/*
 * Decode a base32 string into raw bytes (used to read stored secrets).
 * Returns number of bytes written, or -1 on error.
 */
int base32_decode(const char *encoded, uint8_t *output, size_t output_len);

/*
 * Generate a cryptographically random base32 secret (for user enrollment).
 * Writes null-terminated base32 string into buf.
 * Returns 0 on success, -1 on failure.
 */
int totp_generate_secret(char *buf, size_t buf_len);

/*
 * Read a user's TOTP secret from disk.
 * File is stored at /etc/auth_module/<username>.secret (mode 0600, owned root).
 * Returns decoded bytes written, or -1 if not found / error.
 */
int totp_load_secret(const char *username, uint8_t *secret_buf, size_t buf_len);

#endif /* TOTP_ENGINE_H */
