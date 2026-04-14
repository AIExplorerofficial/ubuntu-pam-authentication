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

## Recovery

If you get locked out, return to the original terminal window (which still has an active session) and run the backup restore command printed by the installer during setup. It will look like:

```bash
sudo cp /etc/pam.d/common-auth.backup.1234567890 /etc/pam.d/common-auth
```

This removes the 2FA requirement and restores your previous configuration immediately.

---

## Audit Log

Every authentication attempt is recorded in a tamper-evident log. To check log integrity at any time:

```bash
sudo ./auth_test --verify-log
```

The command will confirm if the log is intact, or alert you if any entries have been modified or deleted.
