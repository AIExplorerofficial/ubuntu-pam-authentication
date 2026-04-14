#ifndef SECURITY_H
#define SECURITY_H

#include <stddef.h>

/*
 * Security Layer — Rate Limiting, Input Validation, Buffer Protection
 *
 * This addresses the "protect against common vulnerabilities" requirement:
 *
 * 1. BUFFER OVERFLOW PROTECTION
 *    - All string inputs go through sanitize_input() before use
 *    - Explicit length checks before any copy operation
 *    - Never use strcpy, gets, scanf("%s") — always use strncpy + explicit null
 *
 * 2. RATE LIMITING (brute force protection)
 *    - Tracks failed attempts per username in /var/lib/auth_module/
 *    - Lockout after MAX_ATTEMPTS within LOCKOUT_WINDOW seconds
 *    - Lockout duration: LOCKOUT_DURATION seconds
 *
 * 3. TRAPDOOR PREVENTION
 *    - No hardcoded backdoor credentials
 *    - All secrets stored externally (never in source)
 *    - Audit log (see audit_log.h) makes unauthorized access detectable
 */

#define MAX_USERNAME_LEN   64
#define MAX_PASSWORD_LEN   128
#define MAX_ATTEMPTS       5
#define LOCKOUT_WINDOW     300     /* 5 minutes */
#define LOCKOUT_DURATION   900     /* 15 minutes */
#define STATE_DIR          "/var/lib/auth_module"

/*
 * Sanitize a string input — reject anything suspicious.
 * Returns 0 if safe, -1 if the input should be rejected.
 *
 * Rejects: NUL bytes, shell metacharacters, path separators,
 *          strings exceeding max_len.
 */
int sanitize_input(const char *input, size_t max_len);

/*
 * Check if a user is currently locked out.
 * Returns 1 if locked out, 0 if allowed.
 */
int is_locked_out(const char *username);

/*
 * Record a failed authentication attempt.
 * Automatically applies lockout when threshold is reached.
 */
void record_failure(const char *username);

/*
 * Clear failure count after a successful authentication.
 */
void clear_failures(const char *username);

/*
 * Constant-time string comparison — prevents timing attacks.
 * Never use strcmp() to compare secrets or password hashes.
 * Returns 0 if equal, non-zero if different.
 */
int secure_compare(const char *a, const char *b, size_t len);

/*
 * Secure memory wipe — prevents sensitive data from lingering in RAM.
 * Use this on password buffers before freeing/returning.
 * (Regular memset may be optimized away by the compiler; this won't be.)
 */
void secure_wipe(void *buf, size_t len);

#endif /* SECURITY_H */
