#!/usr/bin/env python3
"""
setup_user.py — User Enrollment Tool

This script:
1. Generates a cryptographically random TOTP secret
2. Saves it to /etc/auth_module/<username>.secret (root-only, mode 0600)
3. Prints a QR code that you scan with Google Authenticator / Authy

Run as root:
    sudo python3 setup_user.py <username>

Dependencies:
    pip install qrcode[pil]   # for terminal QR code display
    (or: apt install python3-qrcode)
"""

import sys
import os
import stat
import base64
import hmac
import hashlib
import time
import struct
import secrets
import subprocess

SECRET_DIR = "/etc/auth_module"
SECRET_LEN = 20  # 160-bit secret (same as Google Authenticator default)

def generate_secret() -> str:
    """
    Generate a cryptographically secure base32 secret.
    Uses os.urandom() which reads from /dev/urandom.
    Never use random.random() for secrets.
    """
    raw = secrets.token_bytes(SECRET_LEN)
    # base32 encode, strip padding
    return base64.b32encode(raw).decode('ascii').rstrip('=')

def save_secret(username: str, secret: str):
    """
    Save secret to /etc/auth_module/<username>.secret
    Security requirements:
    - Directory: 0700, owned root
    - File: 0600, owned root
    """
    os.makedirs(SECRET_DIR, mode=0o700, exist_ok=True)

    # Validate username to prevent path traversal
    if '/' in username or '..' in username or not username.isalnum() and '_' not in username:
        raise ValueError(f"Invalid username: {username}")

    path = os.path.join(SECRET_DIR, f"{username}.secret")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(secret + '\n')

    # Ensure permissions are exactly 0600 even if umask interferes
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    print(f"[+] Secret saved to {path} (mode 0600)")

def make_otpauth_url(username: str, secret: str, issuer: str = "AuthModule") -> str:
    """
    Build the otpauth:// URL that QR codes encode.
    Format: otpauth://totp/<issuer>:<username>?secret=<secret>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30
    Reference: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    """
    return (
        f"otpauth://totp/{issuer}:{username}"
        f"?secret={secret}"
        f"&issuer={issuer}"
        f"&algorithm=SHA1"
        f"&digits=6"
        f"&period=30"
    )

def print_qr(url: str):
    """Print QR code to terminal."""
    try:
        import qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data(url)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except ImportError:
        print("[!] Install qrcode for QR display: pip install qrcode[pil]")
        print(f"    Or manually add this URL to your authenticator app:")
        print(f"    {url}")

def totp_verify_interactive(secret: str) -> bool:
    """
    Ask the user to confirm their setup by entering a code.
    This catches misconfigured clocks or wrong secrets before locking out.
    """
    raw = base64.b32decode(secret + '=' * ((8 - len(secret) % 8) % 8))

    code_str = input("\nEnter the 6-digit code from your authenticator to confirm: ").strip()
    if len(code_str) != 6 or not code_str.isdigit():
        return False

    user_code = int(code_str)
    now = int(time.time())

    for window in [-1, 0, 1]:
        counter = struct.pack('>Q', now // 30 + window)
        digest = hmac.new(raw, counter, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        truncated = struct.unpack('>I', digest[offset:offset+4])[0] & 0x7FFFFFFF
        expected = truncated % 1_000_000
        if expected == user_code:
            return True
    return False

def main():
    if os.geteuid() != 0:
        print("Error: Must run as root (sudo python3 setup_user.py <username>)")
        sys.exit(1)

    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <username>")
        sys.exit(1)

    username = sys.argv[1]

    # Check if user exists on the system
    try:
        import pwd
        pwd.getpwnam(username)
    except KeyError:
        print(f"Warning: user '{username}' does not exist on this system.")
        if input("Continue anyway? [y/N]: ").lower() != 'y':
            sys.exit(1)

    secret_path = os.path.join(SECRET_DIR, f"{username}.secret")
    if os.path.exists(secret_path):
        print(f"Warning: {username} is already enrolled.")
        if input("Re-enroll (generates new secret, old authenticator codes stop working)? [y/N]: ").lower() != 'y':
            sys.exit(0)

    # Generate and save secret
    secret = generate_secret()
    save_secret(username, secret)

    # Show enrollment QR code
    url = make_otpauth_url(username, secret)
    print(f"\n[+] Scan this QR code with Google Authenticator / Authy:\n")
    print_qr(url)
    print(f"\n    Manual entry key: {secret}")
    print(f"    Account name:     {username}")
    print(f"    Issuer:           AuthModule")
    print(f"    Algorithm:        SHA1")
    print(f"    Digits:           6")
    print(f"    Period:           30 seconds\n")

    # Verify setup
    if totp_verify_interactive(secret):
        print("[+] Setup verified successfully! MFA is now active for this account.")
    else:
        print("[!] Code did not match. Check your phone's clock sync and try again.")
        print("    The secret has been saved — re-run this script if needed.")

if __name__ == "__main__":
    main()
