/*
 * audit_log.c — Tamper-Evident HMAC-Chained Audit Log
 */

#include "audit_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define HMAC_HEX_LEN   64   /* SHA256 = 32 bytes = 64 hex chars */
#define KEY_LEN        32   /* 256-bit HMAC key */

static const char *event_name(audit_event_t event)
{
    switch (event) {
        case EVT_AUTH_SUCCESS:       return "AUTH_SUCCESS";
        case EVT_AUTH_FAIL_PASSWORD: return "AUTH_FAIL_PASSWORD";
        case EVT_AUTH_FAIL_TOTP:     return "AUTH_FAIL_TOTP";
        case EVT_LOCKOUT:            return "LOCKOUT_APPLIED";
        case EVT_LOCKOUT_CLEARED:    return "LOCKOUT_CLEARED";
        case EVT_USER_ENROLLED:      return "USER_ENROLLED";
        default:                     return "UNKNOWN";
    }
}

/* Load or create the HMAC key for signing log entries */
static int load_hmac_key(uint8_t *key_buf)
{
    FILE *f = fopen(AUDIT_HMAC_KEY_PATH, "rb");
    if (f) {
        size_t n = fread(key_buf, 1, KEY_LEN, f);
        fclose(f);
        return (n == KEY_LEN) ? 0 : -1;
    }

    /* Key doesn't exist — generate one (first run) */
    if (RAND_bytes(key_buf, KEY_LEN) != 1) return -1;

    /* Ensure /etc/auth_module/ exists */
    mkdir("/etc/auth_module", 0700);

    f = fopen(AUDIT_HMAC_KEY_PATH, "wb");
    if (!f) return -1;
    fchmod(fileno(f), 0600);  /* root-only */
    fwrite(key_buf, 1, KEY_LEN, f);
    fclose(f);
    return 0;
}

/* Compute HMAC-SHA256, return as lowercase hex string */
static int compute_hmac(const uint8_t *key, const char *data,
                         char *out_hex, size_t out_len)
{
    if (out_len < HMAC_HEX_LEN + 1) return -1;

    uint8_t digest[32];
    unsigned int digest_len = 0;
    HMAC(EVP_sha256(), key, KEY_LEN,
         (const uint8_t *)data, strlen(data),
         digest, &digest_len);

    if (digest_len != 32) return -1;

    int i;
    for (i = 0; i < 32; i++)
        snprintf(out_hex + i * 2, 3, "%02x", digest[i]);
    out_hex[64] = '\0';
    return 0;
}

/* Read the HMAC of the last line in the log (for chaining) */
static void get_last_hmac(char *last_hmac, size_t hmac_len)
{
    /* Default "genesis" HMAC — used for the very first entry */
    strncpy(last_hmac, "0000000000000000000000000000000000000000000000000000000000000000",
            hmac_len - 1);
    last_hmac[hmac_len - 1] = '\0';

    FILE *f = fopen(AUDIT_LOG_PATH, "r");
    if (!f) return;

    char line[512];
    char prev[512] = "";
    /* Read to the last line */
    while (fgets(line, sizeof(line), f)) {
        strncpy(prev, line, sizeof(prev) - 1);
    }
    fclose(f);

    if (!prev[0]) return;

    /* Log line format: TIMESTAMP|USERNAME|EVENT|HMAC */
    /* Extract the last field (HMAC) */
    char *last_pipe = strrchr(prev, '|');
    if (last_pipe) {
        strncpy(last_hmac, last_pipe + 1, hmac_len - 1);
        /* Strip trailing newline */
        last_hmac[strcspn(last_hmac, "\r\n")] = '\0';
    }
}

void audit_log(const char *username, audit_event_t event)
{
    uint8_t key[KEY_LEN];
    if (load_hmac_key(key) != 0) return;  /* Can't sign — skip logging */

    /* Get current timestamp */
    time_t now = time(NULL);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    /* Get the previous entry's HMAC (for chaining) */
    char prev_hmac[HMAC_HEX_LEN + 2];
    get_last_hmac(prev_hmac, sizeof(prev_hmac));

    const char *evt = event_name(event);

    /*
     * Build the data string that will be HMAC'd.
     * The chain: HMAC covers (prev_hmac + timestamp + username + event)
     * This means any modification to any field, or any insertion/deletion,
     * will break the chain and be detected by audit_verify().
     */
    char data[512];
    snprintf(data, sizeof(data), "%s|%s|%s|%s", prev_hmac, timestamp, username, evt);

    char entry_hmac[HMAC_HEX_LEN + 2];
    if (compute_hmac(key, data, entry_hmac, sizeof(entry_hmac)) != 0) return;

    /* Append to log file (append-only; flock for thread safety) */
    int fd = open(AUDIT_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0640);
    if (fd < 0) return;

    struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_END };
    fcntl(fd, F_SETLKW, &fl);  /* Wait for exclusive lock */

    FILE *f = fdopen(fd, "a");
    if (f) {
        fprintf(f, "%s|%s|%s|%s\n", timestamp, username, evt, entry_hmac);
        fclose(f);  /* Also closes fd */
    }
    fl.l_type = F_UNLCK;
    /* fd is already closed by fclose, but lock is released automatically */
}

int audit_verify(void)
{
    uint8_t key[KEY_LEN];
    if (load_hmac_key(key) != 0) {
        fprintf(stderr, "audit_verify: cannot load HMAC key\n");
        return -1;
    }

    FILE *f = fopen(AUDIT_LOG_PATH, "r");
    if (!f) {
        fprintf(stderr, "audit_verify: log not found\n");
        return 0;  /* Empty log is valid */
    }

    char prev_hmac[HMAC_HEX_LEN + 2];
    strncpy(prev_hmac, "0000000000000000000000000000000000000000000000000000000000000000",
            sizeof(prev_hmac) - 1);

    char line[512];
    int line_num = 0;
    int result = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;
        line[strcspn(line, "\r\n")] = '\0';

        /* Parse: TIMESTAMP|USERNAME|EVENT|HMAC */
        char *fields[4];
        char copy[512];
        strncpy(copy, line, sizeof(copy) - 1);
        char *tok = strtok(copy, "|");
        int i;
        for (i = 0; i < 4 && tok; i++) {
            fields[i] = tok;
            tok = strtok(NULL, "|");
        }
        if (i < 4) {
            fprintf(stderr, "audit_verify: malformed entry at line %d\n", line_num);
            result = -1;
            break;
        }

        char *timestamp = fields[0];
        char *username  = fields[1];
        char *event_str = fields[2];
        char *stored_hmac = fields[3];

        /* Recompute expected HMAC */
        char data[512];
        snprintf(data, sizeof(data), "%s|%s|%s|%s",
                 prev_hmac, timestamp, username, event_str);

        char expected_hmac[HMAC_HEX_LEN + 2];
        compute_hmac(key, data, expected_hmac, sizeof(expected_hmac));

        if (strcmp(expected_hmac, stored_hmac) != 0) {
            fprintf(stderr, "audit_verify: TAMPERING DETECTED at line %d "
                    "(timestamp: %s, user: %s, event: %s)\n",
                    line_num, timestamp, username, event_str);
            result = -1;
            break;
        }

        strncpy(prev_hmac, stored_hmac, sizeof(prev_hmac) - 1);
    }

    fclose(f);
    return result;
}
