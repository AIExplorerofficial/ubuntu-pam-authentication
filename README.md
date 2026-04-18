# Secure 2FA PAM Module for Ubuntu

This module adds two-factor authentication to your Ubuntu system. Once installed, logging in or running sensitive commands will require both your password and a 6-digit code from your phone. It is built specifically for Ubuntu and integrates directly with PAM (Pluggable Authentication Modules).

---

## What You Will Need

- **An Ubuntu system** with `sudo` privileges
- **A smartphone** with an authenticator app installed:
  - Google Authenticator
  - Authy
  - Microsoft Authenticator
  - FreeOTP

---

## Installation

An automated installer script (`install_2fa.sh`) is included. It handles dependencies, compilation, and PAM configuration.

**1. Open a terminal** (`Ctrl + Alt + T`)

**2. Navigate to the project folder:**

```bash
cd /path/to/auth_module
```

**3. Run the installer:**

```bash
sudo bash install_2fa.sh
```

The script will:
- Install any missing dependencies (`python3`, `libpam0g-dev`, etc.)
- Compile and install the PAM module
- Configure Ubuntu's authentication stack to require a TOTP code
- Prompt you to enroll your current user account

When enrollment completes, a QR code will appear in the terminal.

**4. Scan the QR code** using your authenticator app:
- Tap `+` or "Add Account"
- Select "Scan a QR code"
- Point your camera at the terminal

If the QR code does not render, the script will display a plain text setup key instead. In your app, choose "Enter a setup key" and type it in manually.

---

## Testing

**Important:** Keep your current terminal window open before testing. If something goes wrong, you will need it to recover.

Open a second terminal window and run:

```bash
su - your_username
```

The system should prompt for your password, followed by a 6-digit TOTP code. Enter the current code shown in your authenticator app.

If login succeeds, 2FA is active. You can close both terminals.

---

### Recovery (Reliable Method)

If you get locked out due to 2FA, disable it by editing the PAM configuration:

1. Open the file:

   ```bash
   sudo nano /etc/pam.d/common-auth
   ```

2. Locate this exact block at the top of the file:

   ```
   # --- 2FA module (installed by install_2fa.sh) ---
   auth required pam_auth.so
   # --- end 2FA module ---
   ```

3. Comment out ONLY the middle line:

   ```
   # --- 2FA module (installed by install_2fa.sh) ---
   # auth required pam_auth.so
   # --- end 2FA module ---
   ```

4. Save and exit.

This immediately disables 2FA.

To re-enable it, simply uncomment the same line.

---

### Alternative (Backup Restore)

```bash
sudo cp /etc/pam.d/common-auth.backup.<timestamp> /etc/pam.d/common-auth
```

Use this only if the backup file exists.


---

## Audit Log

Every authentication attempt is recorded in a tamper-evident log. To check log integrity at any time:

```bash
sudo ./auth_test --verify-log
```

The command will confirm if the log is intact, or alert you if any entries have been modified or deleted.

---

## Security Features

This section provides a detailed analysis of the security mechanisms implemented in the Secure 2FA PAM Module, including dedicated coverage of buffer overflow and trapdoor prevention.

### Table of Contents

1. [Two-Factor Authentication (2FA / TOTP)](#1-two-factor-authentication-2fa--totp)
2. [Buffer Overflow Protection](#2-buffer-overflow-protection)
3. [Trapdoor Prevention](#3-trapdoor-prevention)
4. [Input Sanitization & Injection Prevention](#4-input-sanitization--injection-prevention)
5. [Rate Limiting & Brute Force Protection](#5-rate-limiting--brute-force-protection)
6. [Secure Memory Management](#6-secure-memory-management)
7. [Cryptographic Security](#7-cryptographic-security)
8. [File System & Privilege Security](#8-file-system--privilege-security)
9. [Tamper-Evident Audit Logging](#9-tamper-evident-audit-logging)
10. [Compiler-Level Security Hardening](#10-compiler-level-security-hardening)
11. [Installer Safety & Rollback](#11-installer-safety--rollback)
12. [Summary Table](#12-summary-table)

---

### 1. Two-Factor Authentication (2FA / TOTP)

The core security feature is **RFC 6238 TOTP (Time-Based One-Time Password)**, adding a second authentication factor on top of the standard Unix password.

| Aspect | Implementation |
|---|---|
| **Algorithm** | HMAC-SHA1 (RFC 4226 HOTP base) |
| **Code length** | 6 digits |
| **Time step** | 30 seconds |
| **Clock skew tolerance** | ±1 window (±30 seconds) |
| **Compatibility** | Google Authenticator, Authy, Microsoft Authenticator, FreeOTP |

**How it works** (`totp_engine.c`):

1. The current Unix time is divided by 30 to get a **time step counter**
2. The counter is encoded as 8 bytes in big-endian format
3. `HMAC-SHA1(secret, counter)` produces a 20-byte digest
4. **Dynamic truncation** extracts a 4-byte slice using the last nibble as an offset
5. Modulo 1,000,000 gives the final 6-digit code

**Security benefit**: Even if an attacker steals the password (Factor 1), they cannot authenticate without the physical device generating TOTP codes (Factor 2).

---

### 2. Buffer Overflow Protection

This project implements explicit buffer overflow prevention at multiple layers.

#### Layer 1: Compiler-Level Protection (`Makefile`)

```c
CFLAGS = -Wall -Wextra -Wpedantic \
         -fstack-protector-strong \
         -D_FORTIFY_SOURCE=2 \
         -fPIC \
         -O2
```

| Flag | Protection |
|---|---|
| `-fstack-protector-strong` | Inserts **stack canaries** — random values placed between local variables and the return address. If a buffer overflow overwrites the canary, the program aborts before the corrupted return address is used. The `strong` variant protects functions that use any local arrays, not just those that call `alloca`. |
| `-D_FORTIFY_SOURCE=2` | At compile time, replaces unsafe glibc functions (`memcpy`, `strcpy`, `sprintf`, etc.) with **bounds-checked variants** that abort if a buffer overflow is detected at runtime. Level 2 adds checks even when the compiler cannot fully determine buffer sizes. |
| `-Wall -Wextra -Wpedantic` | Catches common mistakes (uninitialized variables, implicit conversions, format string mismatches) at **compile time** before they become runtime vulnerabilities. |

#### Layer 2: Explicit Length Checks in Code

Throughout the codebase, every string operation uses **bounded functions**:

- **`snprintf()` instead of `sprintf()`** — all path constructions use `snprintf(path, sizeof(path), ...)` with explicit buffer size, preventing writes beyond the buffer (`security.c`, `totp_engine.c`)
- **`strnlen()` instead of `strlen()`** — input lengths are checked with a maximum cap before processing (`security.c`)
- **`strncpy()` instead of `strcpy()`** — all string copies use bounded variants (`audit_log.c`)
- **`fgets()` instead of `gets()`** — file reads use bounded `fgets(encoded, sizeof(encoded), f)` (`totp_engine.c`)

#### Layer 3: Input Length Validation Before Processing

The `sanitize_input()` function (`security.c`) enforces strict maximum lengths on all user-controlled inputs **before** they are used anywhere:

```c
#define MAX_USERNAME_LEN   64
#define MAX_PASSWORD_LEN   128
```

Both username and password are validated in `pam_sm_authenticate()` (`pam_auth.c`):

```c
if (sanitize_input(username, MAX_USERNAME_LEN) != 0) {
    audit_log("INVALID_INPUT", EVT_AUTH_FAIL_PASSWORD);
    return PAM_AUTH_ERR;
}
```

#### Layer 4: Bounded Buffer Allocations

All local buffers are explicitly sized and passed with `sizeof()`:

- `uint8_t secret[64]` with `totp_load_secret(username, secret, sizeof(secret))` — `pam_auth.c`
- `char path[256]` with `snprintf(path, sizeof(path), ...)` — `security.c`
- `char encoded[SECRET_MAX_LEN + 2]` with `fgets(encoded, sizeof(encoded), f)` — `totp_engine.c`
- `base32_decode()` checks `if (j >= output_len) return -1` before every byte write — `totp_engine.c`

#### Layer 5: `snprintf` Return Value Checking

The `totp_load_secret()` function checks the return value of `snprintf` to detect truncation:

```c
int n = snprintf(path, sizeof(path), "/etc/auth_module/%s.secret", username);
if (n < 0 || n >= (int)sizeof(path)) return -1;
```

This ensures that even if a username is somehow long enough to truncate the path, the function fails safely rather than operating on a truncated (potentially wrong) path.

---

### 3. Trapdoor Prevention

This project includes explicit trapdoor (backdoor) prevention mechanisms, documented in `security.h`.

#### 3.1 No Hardcoded Credentials

The entire codebase contains **zero hardcoded passwords, secrets, or bypass codes**:

- TOTP secrets are generated dynamically using a CSPRNG (`RAND_bytes()` / `secrets.token_bytes()`)
- Secrets are stored in external files (`/etc/auth_module/<user>.secret`), never in source code
- There is no "master password", no debug bypass, and no hidden admin account
- The authentication decision in `pam_sm_authenticate()` has exactly two outcomes: `PAM_SUCCESS` (both factors pass) or `PAM_AUTH_ERR` (any factor fails) — there is no third "backdoor" path

#### 3.2 HMAC-Chained Tamper-Evident Audit Log

The **primary trapdoor detection mechanism** is the audit logging system (`audit_log.c`, `audit_log.h`):

```
Each log entry: TIMESTAMP|USERNAME|EVENT|HMAC-SHA256
```

- Each entry's HMAC covers: `previous_entry_HMAC + timestamp + username + event`
- This creates a **cryptographic chain** (similar to a blockchain)
- If an attacker:
  - **Deletes** a log entry — the chain breaks (next entry's HMAC won't verify)
  - **Modifies** a log entry — the HMAC won't match the recomputed value
  - **Inserts** a fake entry — the chain after the insertion breaks
  - **Reorders** entries — the HMACs won't chain correctly
- Verification is done via `audit_verify()` which replays the entire chain and checks every HMAC
- The HMAC signing key is stored at `/etc/auth_module/audit.key` with `0600` permissions (root-only)

#### 3.3 No Hidden Authentication Paths

The authentication flow in `pam_auth.c` is strictly linear:

1. Get username → validate → reject if invalid
2. Check lockout → reject if locked
3. Get password → validate → reject if invalid
4. Load TOTP secret → reject if not enrolled
5. Prompt for TOTP code → validate → reject if wrong
6. **Only** if all 5 steps pass → `PAM_SUCCESS`

There is no conditional bypass, no environment variable override, no debug flag that skips verification.

#### 3.4 Audit Logging of All Events

Every authentication event is logged with a tamper-evident trail:

| Event Type | When Logged |
|---|---|
| `AUTH_SUCCESS` | Successful login (both factors) |
| `AUTH_FAIL_PASSWORD` | Password wrong or invalid input |
| `AUTH_FAIL_TOTP` | TOTP code wrong |
| `LOCKOUT_APPLIED` | User locked out due to too many failures |
| `LOCKOUT_CLEARED` | Lockout expired |
| `USER_ENROLLED` | New user enrolled in 2FA |

If someone were to install a trapdoor, the audit log would record suspicious authentication successes that don't correspond to legitimate user activity. If they try to cover their tracks by modifying the log, the HMAC chain verification will detect the tampering.

---

### 4. Input Sanitization & Injection Prevention

The `sanitize_input()` function (`security.c`) rejects:

| Threat | Characters Blocked |
|---|---|
| **Shell injection** | `$`, `` ` ``, `\`, `\|`, `;`, `&`, `>`, `<`, `(`, `)`, `{`, `}` |
| **Path traversal** | `/`, `:` (prevents `../etc/passwd` style attacks) |
| **NUL byte injection** | Embedded `\0` bytes |
| **Control characters** | `\n`, `\r`, `\t` |
| **Oversized input** | Anything exceeding `MAX_USERNAME_LEN` (64) or `MAX_PASSWORD_LEN` (128) |
| **Empty input** | Zero-length strings |
| **NULL pointers** | NULL input pointer |

**Path traversal protection** also exists in `totp_load_secret()` (`totp_engine.c`):

```c
if (strstr(path, "..") || strchr(username, '/')) return -1;
```

The Python `setup_user.py` has its own validation:

```python
if '/' in username or '..' in username or not username.isalnum() and '_' not in username:
    raise ValueError(f"Invalid username: {username}")
```

---

### 5. Rate Limiting & Brute Force Protection

Implemented in `security.c` with the following parameters:

| Parameter | Value | Purpose |
|---|---|---|
| `MAX_ATTEMPTS` | 5 | Maximum failures before lockout |
| `LOCKOUT_WINDOW` | 300s (5 min) | Window in which failures are counted |
| `LOCKOUT_DURATION` | 900s (15 min) | How long the lockout persists |

**How it works**:
- Each user's failure count is stored in `/var/lib/auth_module/<username>.fail`
- On every failed authentication, `record_failure()` increments the counter
- Before authentication begins, `is_locked_out()` checks if the user has exceeded `MAX_ATTEMPTS` within the `LOCKOUT_WINDOW`
- On successful authentication, `clear_failures()` resets the counter
- State files are `0600` permissions (root-only read/write)

**Security benefit**: Prevents online brute-force guessing of both passwords and TOTP codes.

---

### 6. Secure Memory Management

#### 6.1 Secure Wipe (`secure_wipe()`)

`security.c`:

```c
void secure_wipe(void *buf, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) *p++ = 0;
}
```

- Uses `volatile` pointer to **prevent the compiler from optimizing away** the zeroing operation
- Applied to TOTP secrets immediately after use (`pam_auth.c`)
- Applied to user-entered TOTP code string immediately after parsing (`pam_auth.c`)
- **Security benefit**: Prevents secrets from lingering in RAM where they could be read via memory dumps, core dumps, or cold boot attacks

#### 6.2 Constant-Time Comparison (`secure_compare()`)

`security.c`:

```c
int secure_compare(const char *a, const char *b, size_t len) {
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++)
        result |= ((unsigned char)a[i]) ^ ((unsigned char)b[i]);
    return (int)result;
}
```

- **Timing attack prevention**: Standard `strcmp()` returns early on first mismatch, leaking information about how many characters an attacker guessed correctly
- This function always processes every byte, keeping execution time constant regardless of where the mismatch occurs
- **Security benefit**: Prevents side-channel attacks where an attacker measures response times to systematically guess secrets

---

### 7. Cryptographic Security

| Aspect | Implementation | Location |
|---|---|---|
| **TOTP HMAC** | HMAC-SHA1 via OpenSSL (audited, industry-standard) | `totp_engine.c` |
| **Audit log signing** | HMAC-SHA256 via OpenSSL | `audit_log.c` |
| **Secret generation** | OpenSSL `RAND_bytes()` (CSPRNG, reads `/dev/urandom`) | `totp_engine.c` |
| **Python secret gen** | `secrets.token_bytes()` (CSPRNG) | `setup_user.py` |
| **Secret entropy** | 160 bits (20 random bytes) | Both C and Python |
| **HMAC key for audit** | 256 bits (32 random bytes), auto-generated on first run | `audit_log.c` |

Note: The project explicitly avoids using `rand()` or `random.random()` for any cryptographic purpose. All randomness comes from CSPRNG sources.

---

### 8. File System & Privilege Security

| Resource | Path | Permissions | Purpose |
|---|---|---|---|
| TOTP secrets | `/etc/auth_module/<user>.secret` | `0600` (root only) | Per-user shared secret |
| Secret directory | `/etc/auth_module/` | `0700` (root only) | Container for secrets |
| Failure state | `/var/lib/auth_module/<user>.fail` | `0600` (root only) | Rate limiting state |
| State directory | `/var/lib/auth_module/` | `0700` (root only) | Container for state files |
| Audit log | `/var/log/auth_module.log` | `0640` | Tamper-evident event log |
| HMAC signing key | `/etc/auth_module/audit.key` | `0600` (root only) | Key for log chain |
| PAM module binary | `/lib/security/pam_auth.so` | `0755` (root owned) | The loadable module |

Additional protections:
- `fchmod(fileno(f), 0600)` is called immediately after file creation to enforce permissions regardless of umask (`security.c`)
- Audit log uses `O_APPEND` flag to enforce append-only writes (`audit_log.c`)
- File locking via `fcntl(fd, F_SETLKW, ...)` ensures thread-safe log writes (`audit_log.c`)

---

### 9. Tamper-Evident Audit Logging

The audit system (`audit_log.c`) implements a **cryptographic hash chain**:

```
Entry 1: HMAC = H(genesis + data₁)
Entry 2: HMAC = H(HMAC₁ + data₂)
Entry 3: HMAC = H(HMAC₂ + data₃)
Entry N: HMAC = H(HMACₙ₋₁ + dataₙ)
```

- Genesis HMAC: 64 zero characters (`0000...0000`)
- Each subsequent entry's HMAC chain includes the previous entry's HMAC
- `audit_verify()` replays the entire chain from genesis to detect any break
- Detectable attacks: **insertion, deletion, modification, and reordering** of log entries

---

### 10. Compiler-Level Security Hardening

From the `Makefile`:

| Flag | Type of Protection |
|---|---|
| `-fstack-protector-strong` | Stack buffer overflow detection via canaries |
| `-D_FORTIFY_SOURCE=2` | Runtime bounds-checking on glibc string/memory functions |
| `-fPIC` | Position-Independent Code (required for shared libs; also enables ASLR effectiveness) |
| `-Wall -Wextra -Wpedantic` | Maximum compile-time warning coverage |
| `-O2` | Required for `_FORTIFY_SOURCE` to be effective |

---

### 11. Installer Safety & Rollback

The installer script (`install_2fa.sh`) includes several safety features:

| Feature | Implementation |
|---|---|
| **Atomic rollback** | Tracks every destructive action in an undo stack; on `ERR`, rolls back in reverse order |
| **PAM backup** | Always creates a timestamped backup of `/etc/pam.d/common-auth` before modification |
| **Root check** | Refuses to run without root privileges |
| **Idempotent re-run** | Detects if PAM is already configured and skips modification |
| **Source validation** | Validates all required source files exist before making any system changes |
| **User existence check** | Verifies the enrollment target user exists on the system |
| **`set -euo pipefail`** | Any unhandled error, unset variable, or pipe failure triggers immediate rollback |

---

### 12. Summary Table

| Security Feature | Status | Key Files |
|---|---|---|
| Two-Factor Authentication (TOTP) | Implemented | `totp_engine.c`, `pam_auth.c` |
| Buffer Overflow — Stack canaries | Implemented | `Makefile` (`-fstack-protector-strong`) |
| Buffer Overflow — FORTIFY_SOURCE | Implemented | `Makefile` (`-D_FORTIFY_SOURCE=2`) |
| Buffer Overflow — Bounded string ops | Implemented | All `.c` files (`snprintf`, `strnlen`, `strncpy`, `fgets`) |
| Buffer Overflow — Input length validation | Implemented | `security.c` (`sanitize_input`) |
| Trapdoor — No hardcoded credentials | Implemented | All files (verified: zero backdoors) |
| Trapdoor — Tamper-evident audit log | Implemented | `audit_log.c` (HMAC-SHA256 chain) |
| Trapdoor — No hidden auth paths | Implemented | `pam_auth.c` (linear auth flow) |
| Input sanitization / injection prevention | Implemented | `security.c`, `totp_engine.c`, `setup_user.py` |
| Rate limiting / brute force protection | Implemented | `security.c` |
| Secure memory wipe | Implemented | `security.c` (volatile wipe) |
| Constant-time comparison | Implemented | `security.c` (timing attack prevention) |
| CSPRNG for secrets | Implemented | `totp_engine.c`, `setup_user.py` |
| Restrictive file permissions | Implemented | `security.c`, `audit_log.c`, `install_2fa.sh` |
| Append-only audit log with file locking | Implemented | `audit_log.c` |
| Installer rollback on failure | Implemented | `install_2fa.sh` |
| Path traversal prevention | Implemented | `totp_engine.c`, `setup_user.py` |
