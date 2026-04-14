/*
 * tests/test_main.c — Standalone test suite
 *
 * This lets you test the TOTP and security logic WITHOUT needing
 * a real PAM setup. Run: make test && ./auth_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/totp_engine.h"
#include "../src/security.h"
#include "../src/audit_log.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name, condition) do { \
    tests_run++; \
    if (condition) { \
        printf("  [PASS] %s\n", name); \
        tests_passed++; \
    } else { \
        printf("  [FAIL] %s\n", name); \
    } \
} while(0)

void test_base32(void)
{
    printf("\n--- Base32 Decode ---\n");

    uint8_t out[32];

    /* Known test vector: "JBSWY3DPEHPK3PXP" decodes to "Hello!" */
    int n = base32_decode("JBSWY3DPEHPK3PXP", out, sizeof(out));
    TEST("known vector length", n == 6);
    TEST("known vector content", n == 6 && memcmp(out, "Hello!", 6) == 0);

    /* Empty input */
    n = base32_decode("", out, sizeof(out));
    TEST("empty input", n == 0);

    /* Invalid character */
    n = base32_decode("JBSWY3DP1234!!!!", out, sizeof(out));
    TEST("invalid chars rejected", n == -1);
}

void test_totp_generate_verify(void)
{
    printf("\n--- TOTP Generate & Verify ---\n");

    /* Generate a fresh secret */
    char secret_b32[64];
    int r = totp_generate_secret(secret_b32, sizeof(secret_b32));
    TEST("secret generation", r == 0 && strlen(secret_b32) > 10);

    /* Decode it */
    uint8_t secret[32];
    int secret_len = base32_decode(secret_b32, secret, sizeof(secret));
    TEST("secret decode", secret_len > 0);

    /* Generate a code and verify it */
    int code = totp_generate(secret, (size_t)secret_len);
    TEST("code is 6 digits", code >= 0 && code <= 999999);

    int valid = totp_verify(secret, (size_t)secret_len, code);
    TEST("generated code verifies", valid == 1);

    /* Verify a wrong code fails */
    int wrong_code = (code + 1) % 1000000;
    int invalid = totp_verify(secret, (size_t)secret_len, wrong_code);
    TEST("wrong code rejected", invalid == 0);

    /* Out-of-range codes */
    TEST("negative code rejected", totp_verify(secret, (size_t)secret_len, -1) == 0);
    TEST("oversized code rejected", totp_verify(secret, (size_t)secret_len, 1000000) == 0);

    printf("    Generated code: %06d (use this in your authenticator app)\n", code);
    printf("    Secret (base32): %s\n", secret_b32);
}

void test_input_sanitization(void)
{
    printf("\n--- Input Sanitization ---\n");

    TEST("normal username OK", sanitize_input("alice", 64) == 0);
    TEST("underscore OK", sanitize_input("alice_bob", 64) == 0);
    TEST("empty rejected", sanitize_input("", 64) == -1);
    TEST("NULL rejected", sanitize_input(NULL, 64) == -1);
    TEST("too long rejected", sanitize_input("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64) == -1);
    TEST("semicolon rejected", sanitize_input("alice;rm -rf /", 64) == -1);
    TEST("path traversal rejected", sanitize_input("../etc/passwd", 64) == -1);
    TEST("dollar sign rejected", sanitize_input("$HOME", 64) == -1);
    TEST("newline rejected", sanitize_input("alice\nroot", 64) == -1);
    TEST("pipe rejected", sanitize_input("alice|cat /etc/shadow", 64) == -1);
}

void test_secure_compare(void)
{
    printf("\n--- Secure Compare ---\n");

    TEST("equal strings", secure_compare("hello", "hello", 5) == 0);
    TEST("different strings", secure_compare("hello", "world", 5) != 0);
    TEST("one-char diff", secure_compare("hella", "hello", 5) != 0);
}

void test_secure_wipe(void)
{
    printf("\n--- Secure Wipe ---\n");

    char buf[32] = "supersecretpassword12345";
    secure_wipe(buf, sizeof(buf));

    int all_zero = 1;
    int i;
    for (i = 0; i < (int)sizeof(buf); i++) {
        if (buf[i] != 0) { all_zero = 0; break; }
    }
    TEST("buffer zeroed", all_zero == 1);
}

void test_audit_log(void)
{
    printf("\n--- Audit Log ---\n");

    /* Write some test entries */
    audit_log("testuser", EVT_AUTH_SUCCESS);
    audit_log("testuser", EVT_AUTH_FAIL_TOTP);
    audit_log("otheruser", EVT_AUTH_FAIL_PASSWORD);

    /* Verify chain integrity */
    int r = audit_verify();
    TEST("log integrity passes", r == 0);

    printf("    Audit log: %s\n", AUDIT_LOG_PATH);
}

int main(int argc, char *argv[])
{
    /* Special mode: just verify the audit log */
    if (argc > 1 && strcmp(argv[1], "--verify-log") == 0) {
        return audit_verify();
    }

    printf("=== Secure Authentication Module — Test Suite ===\n");

    test_base32();
    test_totp_generate_verify();
    test_input_sanitization();
    test_secure_compare();
    test_secure_wipe();
    test_audit_log();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
