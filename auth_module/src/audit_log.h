#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

/*
 * Tamper-Evident Audit Log
 *
 * Addresses "trapdoor protection" requirement:
 * Each log entry contains an HMAC-SHA256 chained from the previous entry.
 * If an attacker tries to delete or modify log entries, the chain breaks
 * and tampering is detectable.
 *
 * Log format (each line):
 *   TIMESTAMP|USERNAME|EVENT|HMAC
 *
 * The HMAC covers: previous_hmac + timestamp + username + event
 * This means you cannot silently insert, delete, or reorder entries.
 *
 * Log location: /var/log/auth_module.log (append-only, root-owned)
 */

#define AUDIT_LOG_PATH     "/var/log/auth_module.log"
#define AUDIT_HMAC_KEY_PATH "/etc/auth_module/audit.key"

typedef enum {
    EVT_AUTH_SUCCESS,
    EVT_AUTH_FAIL_PASSWORD,
    EVT_AUTH_FAIL_TOTP,
    EVT_LOCKOUT,
    EVT_LOCKOUT_CLEARED,
    EVT_USER_ENROLLED
} audit_event_t;

/*
 * Write an audit log entry.
 * Thread-safe via file locking.
 */
void audit_log(const char *username, audit_event_t event);

/*
 * Verify the integrity of the audit log.
 * Returns 0 if intact, -1 if tampering detected.
 * Prints the first tampered entry to stderr.
 */
int audit_verify(void);

#endif /* AUDIT_LOG_H */
