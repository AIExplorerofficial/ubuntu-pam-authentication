/*
 * security.c — Rate Limiting, Input Validation, Buffer Protection
 */
#include <stdint.h>
#include "security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* ── Input Sanitization ─────────────────────────────────────────────────── */

int sanitize_input(const char *input, size_t max_len)
{
    if (!input) return -1;

    size_t len = strnlen(input, max_len + 1);

    /* Reject inputs exceeding max length */
    if (len > max_len) return -1;

    /* Reject empty input */
    if (len == 0) return -1;

    const char *p = input;
    while (*p) {
        unsigned char c = (unsigned char)*p;

        /* Reject NUL bytes embedded in the string */
        if (c == 0) return -1;

        /* Reject shell metacharacters that could enable injection */
        if (c == '$' || c == '`' || c == '\\' || c == '|' ||
            c == ';' || c == '&' || c == '>' || c == '<' ||
            c == '(' || c == ')' || c == '{' || c == '}' ||
            c == '\n' || c == '\r' || c == '\t') {
            return -1;
        }

        /* Reject path separators in usernames */
        if (c == '/' || c == ':') return -1;

        p++;
    }
    return 0;
}

/* ── Secure Memory Operations ───────────────────────────────────────────── */

void secure_wipe(void *buf, size_t len)
{
    /*
     * volatile prevents the compiler from optimizing this away.
     * A smart compiler might see that "buf is never read after this"
     * and skip the memset. volatile forces the write to happen.
     */
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) *p++ = 0;
}

int secure_compare(const char *a, const char *b, size_t len)
{
    /*
     * Constant-time comparison — prevents timing attacks.
     *
     * Why this matters: if we used strcmp(), an attacker could measure
     * response time to guess how many characters match. If "aaaa" takes
     * longer to fail than "bbbb", the first character is 'a'.
     *
     * This implementation always touches every byte regardless of early
     * mismatch, keeping the execution time constant.
     */
    unsigned char result = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        result |= ((unsigned char)a[i]) ^ ((unsigned char)b[i]);
    }
    return (int)result;  /* 0 = equal */
}

/* ── Rate Limiting ──────────────────────────────────────────────────────── */

/*
 * State file format (plain text, one entry per file):
 *   <count>\n<first_attempt_timestamp>\n
 *
 * Each user gets their own file: /var/lib/auth_module/<username>.fail
 * File is owned by root, mode 0600.
 */

static void get_state_path(const char *username, char *path, size_t path_len)
{
    snprintf(path, path_len, "%s/%s.fail", STATE_DIR, username);
}

static void ensure_state_dir(void)
{
    struct stat st;
    if (stat(STATE_DIR, &st) != 0) {
        mkdir(STATE_DIR, 0700);  /* root-only directory */
    }
}

int is_locked_out(const char *username)
{
    char path[256];
    get_state_path(username, path, sizeof(path));

    FILE *f = fopen(path, "r");
    if (!f) return 0;  /* No failure record = not locked out */

    int count = 0;
    time_t first_attempt = 0;
    if (fscanf(f, "%d\n%ld\n", &count, &first_attempt) != 2){
	count=0;
	first_attempt=0;
    }
    	

    fclose(f);

    time_t now = time(NULL);
    double elapsed = difftime(now, first_attempt);

    /* If window has expired, failure record is stale — reset */
    if (elapsed > LOCKOUT_WINDOW) {
        unlink(path);
        return 0;
    }

    /* Locked out if we hit the threshold within the window */
    if (count >= MAX_ATTEMPTS) {
        /* Check if lockout duration has also passed */
        if (elapsed > LOCKOUT_DURATION) {
            unlink(path);
            return 0;
        }
        return 1;  /* Still locked out */
    }

    return 0;
}

void record_failure(const char *username)
{
    ensure_state_dir();

    char path[256];
    get_state_path(username, path, sizeof(path));

    int count = 0;
    time_t first_attempt = time(NULL);

    /* Read existing record if any */
    FILE *f = fopen(path, "r");
    if (f) {
        if (fscanf(f, "%d\n%ld\n", &count, &first_attempt) != 2){
		count=0;
		first_attempt = 0;
	}
        

        fclose(f);
    }

    count++;

    /* Write updated record */
    f = fopen(path, "w");
    if (f) {
        /* Restrict to root-only read/write */
        fchmod(fileno(f), 0600);
        fprintf(f, "%d\n%ld\n", count, (long)first_attempt);
        fclose(f);
    }
}

void clear_failures(const char *username)
{
    char path[256];
    get_state_path(username, path, sizeof(path));
    unlink(path);  /* Remove the failure record on successful auth */
}
