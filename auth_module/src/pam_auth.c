/*
 * pam_auth.c — PAM Module (OS Integration Layer)
 *
 * PAM = Pluggable Authentication Modules — the standard Linux/macOS
 * authentication framework. Every login (ssh, sudo, su, login) goes
 * through PAM. By writing a PAM module, we hook into ALL of these
 * simultaneously without touching any individual application.
 *
 * How to install (after building):
 *   sudo cp pam_auth.so /lib/security/pam_auth.so
 *   Add to /etc/pam.d/sshd:
 *     auth required pam_auth.so
 *
 * References:
 *   - Linux-PAM documentation: https://www.linux-pam.org/Linux-PAM-html/
 *   - PAM API: /usr/include/security/pam_modules.h
 */

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "totp_engine.h"
#include "security.h"
#include "audit_log.h"

#define TOTP_PROMPT "Authenticator code: "

/* ── PAM Authentication Entry Point ────────────────────────────────────── */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;  /* unused */

    /* ── Step 1: Get username ─────────────────────────────────────────── */
    const char *username = NULL;
    int pam_err = pam_get_user(pamh, &username, "Username: ");
    if (pam_err != PAM_SUCCESS || !username) return PAM_AUTH_ERR;

    /*
     * Buffer overflow protection: reject oversized or suspicious usernames
     * before doing anything else with them.
     */
    if (sanitize_input(username, MAX_USERNAME_LEN) != 0) {
        audit_log("INVALID_INPUT", EVT_AUTH_FAIL_PASSWORD);
        return PAM_AUTH_ERR;
    }

    /* ── Step 2: Check rate limiting ──────────────────────────────────── */
    if (is_locked_out(username)) {
        pam_error(pamh, "Account temporarily locked. Try again later.");
        audit_log(username, EVT_LOCKOUT);
        return PAM_MAXTRIES;
    }

    /* ── Step 3: Factor 1 — Password ─────────────────────────────────── */
    /*
     * pam_get_authtok asks PAM's stack for the password.
     * If another module (like pam_unix) already collected it, we reuse it.
     * If not, PAM prompts the user. This avoids double-prompting.
     */
    const char *password = NULL;
    pam_err = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (pam_err != PAM_SUCCESS || !password) {
        record_failure(username);
        audit_log(username, EVT_AUTH_FAIL_PASSWORD);
        return PAM_AUTH_ERR;
    }

    if (sanitize_input(password, MAX_PASSWORD_LEN) != 0) {
        record_failure(username);
        audit_log(username, EVT_AUTH_FAIL_PASSWORD);
        return PAM_AUTH_ERR;
    }

    /*
     * NOTE: In a real deployment, password verification is done by pam_unix
     * (which checks /etc/shadow). Our module sits ON TOP and adds TOTP.
     * The PAM stack handles factor 1; we handle factor 2.
     *
     * For standalone testing without pam_unix, you'd implement password
     * checking here using crypt(3) against /etc/shadow. We skip that to
     * avoid duplicating what the OS already does perfectly.
     */

    /* ── Step 4: Factor 2 — TOTP ──────────────────────────────────────── */
    uint8_t secret[64];
    int secret_len = totp_load_secret(username, secret, sizeof(secret));
    if (secret_len <= 0) {
        /*
         * User not enrolled in TOTP. Policy decision:
         * - Return PAM_SUCCESS to allow login without TOTP (optional MFA)
         * - Return PAM_AUTH_ERR to require TOTP for everyone
         *
         * For this implementation, we REQUIRE enrollment.
         */
        pam_error(pamh, "TOTP not configured for this account. "
                        "Run setup_user.py to enroll.");
        secure_wipe(secret, sizeof(secret));
        return PAM_AUTH_ERR;
    }

    /* Prompt for the 6-digit code */
    char *totp_str = NULL;
    struct pam_conv *conv = NULL;
    pam_get_item(pamh, PAM_CONV, (const void **)&conv);

    if (!conv || !conv->conv) {
        secure_wipe(secret, sizeof(secret));
        return PAM_AUTH_ERR;
    }

    struct pam_message msg = {
        .msg_style = PAM_PROMPT_ECHO_ON,
        .msg = TOTP_PROMPT
    };
    const struct pam_message *msgs[] = { &msg };
    struct pam_response *resp = NULL;

    int conv_err = conv->conv(1, msgs, &resp, conv->appdata_ptr);
    if (conv_err != PAM_SUCCESS || !resp || !resp->resp) {
        free(resp);
        secure_wipe(secret, sizeof(secret));
        return PAM_AUTH_ERR;
    }

    totp_str = resp->resp;

    /* Validate: must be exactly 6 digits */
    if (strlen(totp_str) != 6) {
        free(resp);
        secure_wipe(secret, sizeof(secret));
        record_failure(username);
        audit_log(username, EVT_AUTH_FAIL_TOTP);
        return PAM_AUTH_ERR;
    }

    int code = atoi(totp_str);

    /* Wipe the code from memory immediately after parsing */
    secure_wipe(totp_str, strlen(totp_str));
    free(resp);

    int totp_valid = totp_verify(secret, (size_t)secret_len, code);
    secure_wipe(secret, sizeof(secret));  /* Wipe secret from memory */

    /* ── Step 5: Final decision ───────────────────────────────────────── */
    if (!totp_valid) {
        record_failure(username);
        audit_log(username, EVT_AUTH_FAIL_TOTP);
        pam_error(pamh, "Invalid authenticator code.");
        return PAM_AUTH_ERR;
    }

    /* Both factors passed */
    clear_failures(username);
    audit_log(username, EVT_AUTH_SUCCESS);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

/* Required exports for PAM dynamic loading */
#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_auth");
#endif
