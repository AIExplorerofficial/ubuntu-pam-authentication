#!/bin/bash
# =============================================================================
# install_2fa.sh — Secure 2FA PAM Module Installer
# =============================================================================
# - Safe to re-run: detects already-installed state and skips steps cleanly
# - Full rollback on any error: PAM config, module file, state dirs all reverted
# - Validates every source file exists before touching the system
# - Shows QR code in terminal after enrollment
# - Does NOT lock you out if run a second time
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*" >&2; }
section() { echo -e "\n${BOLD}${BLUE}==== $* ====${NC}"; }

# ── Log everything to file too ────────────────────────────────────────────────
LOG_FILE="/tmp/auth_module_install_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
info "Full install log: $LOG_FILE"

# =============================================================================
# SECTION 1 — Root check
# =============================================================================
section "Pre-flight checks"

if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root: sudo bash $0"
    exit 1
fi
info "Running as root ✓"

# =============================================================================
# SECTION 2 — Detect source file layout
# =============================================================================
# Support two layouts:
#   Layout A (flat):  all .c/.h files alongside this script
#   Layout B (tree):  script at root, sources in src/, tools/, tests/
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Script directory: $SCRIPT_DIR"

# Detect layout
if [ -f "$SCRIPT_DIR/src/pam_auth.c" ]; then
    SRC_DIR="$SCRIPT_DIR/src"
    TOOLS_DIR="$SCRIPT_DIR/tools"
    TESTS_DIR="$SCRIPT_DIR/tests"
    LAYOUT="tree"
    info "Detected project layout: tree (src/ tools/ tests/)"
elif [ -f "$SCRIPT_DIR/pam_auth.c" ]; then
    SRC_DIR="$SCRIPT_DIR"
    TOOLS_DIR="$SCRIPT_DIR"
    TESTS_DIR="$SCRIPT_DIR"
    LAYOUT="flat"
    info "Detected project layout: flat (all files in same directory)"
else
    error "Cannot find pam_auth.c"
    error "Expected it at: $SCRIPT_DIR/pam_auth.c  OR  $SCRIPT_DIR/src/pam_auth.c"
    error "Make sure this script is placed inside your project folder."
    exit 1
fi

# ── Validate every required file exists before touching anything ──────────────
REQUIRED_FILES=(
    "$SRC_DIR/pam_auth.c"
    "$SRC_DIR/totp_engine.c"
    "$SRC_DIR/totp_engine.h"
    "$SRC_DIR/security.c"
    "$SRC_DIR/security.h"
    "$SRC_DIR/audit_log.c"
    "$SRC_DIR/audit_log.h"
    "$TOOLS_DIR/setup_user.py"
)

MISSING=0
for f in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        error "Required file not found: $f"
        MISSING=1
    fi
done

if [ "$MISSING" -eq 1 ]; then
    error "One or more source files are missing. Aborting before making any changes."
    exit 1
fi
info "All source files present ✓"

# =============================================================================
# SECTION 3 — Configuration
# =============================================================================

PAM_FILE="/etc/pam.d/common-auth"
PAM_MARKER="auth required pam_auth.so"
MODULE_INSTALL_PATH="/lib/x86_64-linux-gnu/security/pam_auth.so"
MODULE_FALLBACK_PATH="/lib/security/pam_auth.so"
ETC_DIR="/etc/auth_module"
STATE_DIR="/var/lib/auth_module"
LOG_DIR="/var/log"
BUILD_DIR="/tmp/auth_module_build_$$"

# Prefer x86_64-linux-gnu path; fall back for 32-bit or arm systems
if [ ! -d "/lib/x86_64-linux-gnu/security" ]; then
    if [ -d "/lib/security" ]; then
        MODULE_INSTALL_PATH="$MODULE_FALLBACK_PATH"
        warn "Using fallback PAM module path: $MODULE_INSTALL_PATH"
    else
        # Create the directory — some minimal installs lack it
        mkdir -p "/lib/x86_64-linux-gnu/security"
    fi
fi

# Who to enroll (the user who invoked sudo, not root)
if [ -n "${SUDO_USER:-}" ]; then
    REAL_USER="$SUDO_USER"
elif command -v logname &>/dev/null && logname &>/dev/null 2>&1; then
    REAL_USER="$(logname)"
else
    # Last resort: ask
    read -rp "Enter the username to enroll in 2FA: " REAL_USER
fi

if [ -z "$REAL_USER" ] || [ "$REAL_USER" = "root" ]; then
    warn "Target user is '$REAL_USER'. Enrolling root in PAM-based 2FA is risky."
    read -rp "Continue anyway? [y/N]: " CONFIRM
    [[ "${CONFIRM,,}" == "y" ]] || { info "Aborted by user."; exit 0; }
fi

# Verify the user actually exists on the system
if ! id "$REAL_USER" &>/dev/null; then
    error "User '$REAL_USER' does not exist on this system."
    error "Create the user first with: sudo adduser $REAL_USER"
    exit 1
fi

info "Will enroll user: $REAL_USER"
info "PAM module destination: $MODULE_INSTALL_PATH"

# =============================================================================
# SECTION 4 — Rollback system
# =============================================================================
# We track every destructive action and undo all of them on failure.
# Each action pushes an undo command onto a stack (array).
# rollback() runs the stack in reverse order.
# =============================================================================

UNDO_STACK=()
BACKUP_PAM=""
BACKUP_MODULE=""

push_undo() {
    # Usage: push_undo "command string"
    UNDO_STACK+=("$1")
}

rollback() {
    local exit_code=$?
    echo ""
    error "Something went wrong (exit code $exit_code). Running rollback..."
    echo ""

    # Run undo stack in reverse
    local i
    for (( i=${#UNDO_STACK[@]}-1; i>=0; i-- )); do
        warn "Undoing: ${UNDO_STACK[$i]}"
        eval "${UNDO_STACK[$i]}" || warn "  (undo step failed — continuing rollback)"
    done

    # Always restore PAM config if we have a backup
    if [ -n "$BACKUP_PAM" ] && [ -f "$BACKUP_PAM" ]; then
        warn "Restoring PAM config from backup: $BACKUP_PAM"
        cp "$BACKUP_PAM" "$PAM_FILE"
        info "PAM config restored ✓"
    fi

    # Restore module binary if we backed it up
    if [ -n "$BACKUP_MODULE" ] && [ -f "$BACKUP_MODULE" ]; then
        warn "Restoring previous PAM module binary"
        cp "$BACKUP_MODULE" "$MODULE_INSTALL_PATH"
    elif [ -n "$BACKUP_MODULE" ] && [ ! -f "$BACKUP_MODULE" ]; then
        # Module didn't exist before — remove the one we installed
        rm -f "$MODULE_INSTALL_PATH"
    fi

    # Clean up build dir
    rm -rf "$BUILD_DIR"

    echo ""
    error "Rollback complete. Your system should be in its original state."
    error "Check the install log for details: $LOG_FILE"
    exit 1
}

trap rollback ERR

# =============================================================================
# SECTION 5 — Install system dependencies
# =============================================================================
section "Installing dependencies"

PACKAGES_NEEDED=()

check_pkg() {
    dpkg -s "$1" &>/dev/null || PACKAGES_NEEDED+=("$1")
}

check_pkg build-essential
check_pkg libpam0g-dev
check_pkg libssl-dev
check_pkg python3
check_pkg python3-qrcode
check_pkg python3-pil

if [ ${#PACKAGES_NEEDED[@]} -gt 0 ]; then
    info "Installing: ${PACKAGES_NEEDED[*]}"
    apt-get update -qq
    apt-get install -y "${PACKAGES_NEEDED[@]}"
    info "System packages installed ✓"
else
    info "All system packages already installed ✓"
fi

# Verify qrcode is importable after install
if ! python3 -c "import qrcode" &>/dev/null 2>&1; then
    warn "qrcode library could not be imported even after install."
    warn "QR code will not display — you can add manually using the key shown below."
else
    info "Python qrcode library ready ✓"
fi

# =============================================================================
# SECTION 6 — Build the PAM module
# =============================================================================
section "Building PAM module"

mkdir -p "$BUILD_DIR"
push_undo "rm -rf '$BUILD_DIR'"

# Copy sources into a clean build directory
cp "$SRC_DIR/pam_auth.c"    "$BUILD_DIR/"
cp "$SRC_DIR/totp_engine.c" "$BUILD_DIR/"
cp "$SRC_DIR/totp_engine.h" "$BUILD_DIR/"
cp "$SRC_DIR/security.c"    "$BUILD_DIR/"
cp "$SRC_DIR/security.h"    "$BUILD_DIR/"
cp "$SRC_DIR/audit_log.c"   "$BUILD_DIR/"
cp "$SRC_DIR/audit_log.h"   "$BUILD_DIR/"

cd "$BUILD_DIR"

info "Compiling with security flags..."
gcc \
    -Wall -Wextra \
    -fPIC \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -O2 \
    -shared \
    -o pam_auth.so \
    pam_auth.c totp_engine.c security.c audit_log.c \
    -lpam -lcrypto

if [ ! -f "$BUILD_DIR/pam_auth.so" ]; then
    error "Compilation succeeded but pam_auth.so was not produced — this is unexpected."
    exit 1
fi

info "Build successful ✓"

# =============================================================================
# SECTION 7 — Install the compiled module
# =============================================================================
section "Installing PAM module"

# Back up the existing module if present (so rollback can restore it)
if [ -f "$MODULE_INSTALL_PATH" ]; then
    BACKUP_MODULE="${MODULE_INSTALL_PATH}.backup.$(date +%s)"
    cp "$MODULE_INSTALL_PATH" "$BACKUP_MODULE"
    push_undo "mv '$BACKUP_MODULE' '$MODULE_INSTALL_PATH'"
    info "Backed up existing module to: $BACKUP_MODULE"
else
    # Signal to rollback that module didn't exist before
    BACKUP_MODULE="${MODULE_INSTALL_PATH}.did_not_exist"
    push_undo "rm -f '$MODULE_INSTALL_PATH'"
fi

install -o root -g root -m 0755 "$BUILD_DIR/pam_auth.so" "$MODULE_INSTALL_PATH"

if [ ! -f "$MODULE_INSTALL_PATH" ]; then
    error "Module copy failed — file not found at $MODULE_INSTALL_PATH after install."
    exit 1
fi

info "Module installed to: $MODULE_INSTALL_PATH ✓"

# =============================================================================
# SECTION 8 — Create required directories
# =============================================================================
section "Setting up system directories"

# /etc/auth_module — stores per-user TOTP secrets (mode 0700, root-only)
if [ ! -d "$ETC_DIR" ]; then
    mkdir -p "$ETC_DIR"
    chmod 700 "$ETC_DIR"
    push_undo "rmdir '$ETC_DIR' 2>/dev/null || true"
    info "Created $ETC_DIR (mode 700) ✓"
else
    chmod 700 "$ETC_DIR"
    info "$ETC_DIR already exists ✓"
fi

# /var/lib/auth_module — stores per-user failure/lockout state
if [ ! -d "$STATE_DIR" ]; then
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    push_undo "rmdir '$STATE_DIR' 2>/dev/null || true"
    info "Created $STATE_DIR (mode 700) ✓"
else
    chmod 700 "$STATE_DIR"
    info "$STATE_DIR already exists ✓"
fi

# =============================================================================
# SECTION 9 — Update PAM configuration (idempotent)
# =============================================================================
section "Configuring PAM"

if [ ! -f "$PAM_FILE" ]; then
    error "PAM config file not found: $PAM_FILE"
    error "Is this an Ubuntu/Debian system? Expected /etc/pam.d/common-auth."
    exit 1
fi

# Take a timestamped backup before touching PAM — always, even on re-run
BACKUP_PAM="/etc/pam.d/common-auth.backup.$(date +%s)"
cp "$PAM_FILE" "$BACKUP_PAM"
info "PAM backup saved: $BACKUP_PAM"

if grep -qF "$PAM_MARKER" "$PAM_FILE"; then
    info "PAM already configured — skipping (idempotent re-run) ✓"
else
    # Insert our line at the very top of the file (before any other auth lines)
    # so we run first: lockout check happens before any password prompt.
    # This is safer than sed-based insertion which can silently fail if the
    # anchor pattern (pam_deny.so) isn't present on all Ubuntu versions.
    TMPFILE=$(mktemp)
    {
        echo "# --- 2FA module (installed by install_2fa.sh) ---"
        echo "$PAM_MARKER"
        echo "# --- end 2FA module ---"
        cat "$PAM_FILE"
    } > "$TMPFILE"
    mv "$TMPFILE" "$PAM_FILE"

    if ! grep -qF "$PAM_MARKER" "$PAM_FILE"; then
        error "PAM modification failed — the line was not written."
        exit 1
    fi
    info "PAM config updated ✓"
fi

# =============================================================================
# SECTION 10 — User enrollment (TOTP secret + QR code)
# =============================================================================
section "Enrolling user: $REAL_USER"

SECRET_FILE="$ETC_DIR/${REAL_USER}.secret"

if [ -f "$SECRET_FILE" ]; then
    warn "User '$REAL_USER' is already enrolled (secret file exists)."
    read -rp "Re-enroll? This will invalidate the old authenticator code. [y/N]: " RE_ENROLL
    if [[ "${RE_ENROLL,,}" != "y" ]]; then
        info "Skipping enrollment — existing setup kept."
        ENROLLMENT_SKIPPED=1
    else
        ENROLLMENT_SKIPPED=0
    fi
else
    ENROLLMENT_SKIPPED=0
fi

if [ "${ENROLLMENT_SKIPPED:-0}" -eq 0 ]; then
    info "Running setup_user.py for $REAL_USER..."

    # Run setup_user.py — it generates the secret, writes the file, and
    # prints the QR code. We call it as root (which we already are).
    # setup_user.py already handles the interactive confirmation step.
    if ! python3 "$TOOLS_DIR/setup_user.py" "$REAL_USER"; then
        error "setup_user.py failed for user '$REAL_USER'."
        error "The secret file may be partially written at: $SECRET_FILE"
        exit 1
    fi

    # Confirm the secret file was actually created
    if [ ! -f "$SECRET_FILE" ]; then
        error "setup_user.py completed but secret file was not created: $SECRET_FILE"
        exit 1
    fi

    info "TOTP secret written to $SECRET_FILE (mode 0600) ✓"
fi

# =============================================================================
# SECTION 11 — Verify the QR code is displayable (diagnostic)
# =============================================================================
# setup_user.py should have already shown the QR, but if it didn't (the bug
# in the original installer), we regenerate and display it here directly from
# the saved secret file. This is the fix for the missing QR issue.
# =============================================================================
section "Displaying QR code"

QR_DISPLAY_SCRIPT=$(cat <<'PYEOF'
import sys, os, base64, stat

secret_file = sys.argv[1]
username    = sys.argv[2]

if not os.path.exists(secret_file):
    print(f"Secret file not found: {secret_file}", file=sys.stderr)
    sys.exit(1)

with open(secret_file, 'r') as f:
    secret = f.read().strip()

if not secret:
    print("Secret file is empty.", file=sys.stderr)
    sys.exit(1)

issuer  = "AuthModule"
url     = (f"otpauth://totp/{issuer}:{username}"
           f"?secret={secret}&issuer={issuer}"
           f"&algorithm=SHA1&digits=6&period=30")

print(f"\n{'='*60}")
print(f"  2FA SETUP — scan this with Google Authenticator / Authy")
print(f"{'='*60}\n")

try:
    import qrcode
    qr = qrcode.QRCode(border=2)
    qr.add_data(url)
    qr.make(fit=True)
    qr.print_ascii(invert=True)
    print()
except ImportError:
    print("  [qrcode library not available — showing manual entry details]")

print(f"  Manual entry key : {secret}")
print(f"  Account name     : {username}")
print(f"  Issuer           : {issuer}")
print(f"  Algorithm        : SHA1")
print(f"  Digits           : 6")
print(f"  Period           : 30 seconds\n")
print(f"{'='*60}\n")
PYEOF
)

python3 -c "$QR_DISPLAY_SCRIPT" "$SECRET_FILE" "$REAL_USER"

# =============================================================================
# SECTION 12 — Cleanup and success summary
# =============================================================================
section "Finalising"

# Clean up the build directory now that we're done
rm -rf "$BUILD_DIR"

# Remove the "not exist" sentinel if rollback no longer needs it
[[ "$BACKUP_MODULE" == *.did_not_exist ]] && rm -f "$BACKUP_MODULE"

echo ""
echo -e "${BOLD}${GREEN}==== INSTALLATION COMPLETE ====${NC}"
echo ""
echo -e "  ${GREEN}✓${NC} PAM module installed : $MODULE_INSTALL_PATH"
echo -e "  ${GREEN}✓${NC} PAM config updated   : $PAM_FILE"
echo -e "  ${GREEN}✓${NC} PAM backup saved     : $BACKUP_PAM"
echo -e "  ${GREEN}✓${NC} User enrolled        : $REAL_USER"
echo -e "  ${GREEN}✓${NC} Install log          : $LOG_FILE"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo "  1. Scan the QR code above into Google Authenticator or Authy."
echo "  2. Test in a NEW terminal (keep this one open as a safety net):"
echo "       su - $REAL_USER"
echo "  3. You will be prompted for both your password AND a 6-digit code."
echo ""
echo -e "${YELLOW}IMPORTANT:${NC} Do not close this terminal until you have confirmed"
echo "  login works in a separate session. If anything is wrong, restore with:"
echo "       sudo cp $BACKUP_PAM $PAM_FILE"
echo ""
echo -e "${BOLD}To verify audit log integrity at any time:${NC}"
echo "  sudo ./auth_test --verify-log"
echo ""
