#!/usr/bin/env bash
####################################################
# Description: Add Yubikey 2FA for macOS
# Version: 0.1
# Author: jnqpblc
# LICENSE: MIT
####################################################
set -euo pipefail

# install_yubikey_sudo.sh
# Enhanced installer: installs YubiKey-related packages, registers U2F keys,
# and can safely modify PAM sudo configuration. Interactive (alacarte) or
# batch (--all) modes supported. Strong warnings included.

PROGNAME=$(basename "$0")
TARGET_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo "~$TARGET_USER")
AUTHFILE="$USER_HOME/.config/Yubico/u2f_keys"
TIMESTAMP=$(date +%s)
BACKUP_DIR="/etc/pam.d"

INSTALL_PAM_U2F=false
INSTALL_OPENSC=false
INSTALL_YKMAN=false
MODIFY_PAM=false
PIV_MODE=false
PIV_CERT_PATH=""
ENROLL_SMARTCARD=false
ALACARTE=false
ASSUME_YES=false

print_help() {
    cat <<EOF
Usage: $PROGNAME [options]

Options:
  --all             Install pam-u2f, opensc, and yubikey-manager
  --pam-u2f         Install pam-u2f (pamu2fcfg)
  --opensc          Install OpenSC (PKCS#11 / smartcard support)
  --ykman           Install yubikey-manager (ykman)
  --modify-pam      Modify /etc/pam.d/sudo to require U2F
  --services=LIST   Comma-separated PAM services to modify (default: sudo)
  --alacarte        Interactive selection menu
  -y, --yes         Assume yes to prompts
  -h, --help        Show this help

Examples:
  $PROGNAME --all --modify-pam
  $PROGNAME --pam-u2f --alacarte

WARNING: Modifying PAM can lock you out. Open a root terminal or have
recovery access available before running. Proceed at your own risk.
EOF
}

services_to_modify=(sudo)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)
            INSTALL_PAM_U2F=true
            INSTALL_OPENSC=true
            INSTALL_YKMAN=true
            shift
            ;;
        --pam-u2f)
            INSTALL_PAM_U2F=true
            shift
            ;;
        --opensc)
            INSTALL_OPENSC=true
            shift
            ;;
        --ykman)
            INSTALL_YKMAN=true
            shift
            ;;
        --modify-pam)
            MODIFY_PAM=true
            shift
            ;;
        --services=*)
            IFS=',' read -r -a services_to_modify <<< "${1#*=}"
            shift
            ;;
        --alacarte)
            ALACARTE=true
            shift
            ;;
        --piv)
            PIV_MODE=true
            INSTALL_OPENSC=true
            INSTALL_YKMAN=true
            shift
            ;;
        --enroll-smartcard)
            ENROLL_SMARTCARD=true
            shift
            ;;
        --piv-cert=*)
            PIV_CERT_PATH="${1#*=}"
            shift
            ;;
        -y|--yes)
            ASSUME_YES=true
            shift
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_help
            exit 1
            ;;
    esac
done

if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew not found. Install Homebrew first: https://brew.sh/"
    exit 1
fi

echo "Target user: $TARGET_USER"

if [ "$ALACARTE" = true ]; then
    echo "Interactive package selection:"
    read -p "Install pam-u2f (pamu2fcfg)? (y/N) " ans && [[ $ans =~ ^[Yy] ]] && INSTALL_PAM_U2F=true
    read -p "Install OpenSC (smartcard / PKCS#11)? (y/N) " ans && [[ $ans =~ ^[Yy] ]] && INSTALL_OPENSC=true
    read -p "Install yubikey-manager (ykman)? (y/N) " ans && [[ $ans =~ ^[Yy] ]] && INSTALL_YKMAN=true
    read -p "Modify PAM services (${services_to_modify[*]}) to require U2F? (y/N) " ans && [[ $ans =~ ^[Yy] ]] && MODIFY_PAM=true
fi

echo
echo "WARNING: Modifying PAM or installing auth modules can lock you out of the system."
echo "It is strongly recommended to run this from a root terminal or have recovery access."
if [ "$ASSUME_YES" = false ]; then
    read -p "Proceed? (y/N) " proceed
    if [[ ! $proceed =~ ^[Yy] ]]; then
        echo "Aborted by user."
        exit 1
    fi
fi

install_if_missing() {
    pkg="$1"
    formula="$2"
    if brew list --formula | grep -q "^${formula}$" 2>/dev/null; then
        echo "${pkg} already installed; skipping."
        return 0
    fi
    echo "Installing ${pkg} (${formula})..."
    # suppress Homebrew install cleanup and env hints
    export HOMEBREW_NO_INSTALL_CLEANUP=1
    export HOMEBREW_NO_ENV_HINTS=1
    if [ "$TARGET_USER" != "$(whoami)" ]; then
        if ! sudo -u "$TARGET_USER" brew install "$formula"; then
            return 1
        fi
    else
        if ! brew install "$formula"; then
            return 1
        fi
    fi
    return 0
}

if [ "$INSTALL_PAM_U2F" = true ]; then
    install_if_missing "pam-u2f" "pam-u2f"
fi

if [ "$INSTALL_OPENSC" = true ]; then
    install_if_missing "OpenSC" "opensc"
fi

if [ "$INSTALL_YKMAN" = true ]; then
    # Try primary formula first; if not available, try alternatives/cask/pipx
    if install_if_missing "yubikey-manager" "yubikey-manager"; then
        true
    else
        echo "Primary 'yubikey-manager' formula not available; trying alternatives..."
        if install_if_missing "yubikey-agent" "yubikey-agent"; then
            echo "Installed yubikey-agent as an alternative."
        else
            echo "yubikey-agent not available or failed. Trying cask 'yubico-authenticator'..."
            # try cask install
            if brew list --cask | grep -q "^yubico-authenticator$" 2>/dev/null; then
                echo "yubico-authenticator already installed as cask; skipping."
            else
                export HOMEBREW_NO_INSTALL_CLEANUP=1
                export HOMEBREW_NO_ENV_HINTS=1
                if ! brew install --cask yubico-authenticator 2>/dev/null; then
                    echo "cask install of yubico-authenticator failed or is unavailable."
                    # try pipx fallback to install yubikey-manager (provides ykman)
                    if command -v pipx >/dev/null 2>&1; then
                        echo "Attempting pipx install of yubikey-manager (ykman)..."
                        if pipx install yubikey-manager; then
                            echo "Installed yubikey-manager via pipx."
                        else
                            echo "pipx install failed. You may need to install yubikey-manager manually."
                        fi
                    else
                        echo "pipx not found; to get the 'ykman' CLI consider installing pipx and running: pipx install yubikey-manager"
                    fi
                else
                    echo "Installed yubico-authenticator cask."
                fi
            fi
        fi
    fi
fi

# PIV (smartcard) guidance and optional cert import
if [ "$PIV_MODE" = true ]; then
    echo "PIV mode requested: yubikey-manager and OpenSC were installed (if requested)."
    if ! command -v ykman >/dev/null 2>&1; then
        echo "ykman not found; ensure yubikey-manager installed correctly."
    else
        echo "Detected ykman; you can manage PIV keys with: ykman piv --help"
    fi

    if [[ -n "$PIV_CERT_PATH" ]]; then
        if [ -f "$PIV_CERT_PATH" ]; then
            echo "Importing certificate $PIV_CERT_PATH into the System keychain (requires sudo)."
            if sudo security import "$PIV_CERT_PATH" -k /Library/Keychains/System.keychain 2>/dev/null; then
                echo "Imported $PIV_CERT_PATH into /Library/Keychains/System.keychain"
            else
                echo "security import failed; you may need to run this script with sudo or import manually"
            fi

            echo "To mark the certificate trusted for login, you can run (requires sudo):"
            echo "  sudo security add-trusted-cert -d -r trustAsRoot -k /Library/Keychains/System.keychain $PIV_CERT_PATH"

            # If requested, attempt to enroll this certificate for smartcard login using sc_auth
            if [ "$ENROLL_SMARTCARD" = true ]; then
                if command -v sc_auth >/dev/null 2>&1; then
                    echo "Attempting to enroll smartcard login for user $TARGET_USER using sc_auth (requires sudo)."
                    echo "This will map the certificate on the YubiKey to the local account for smartcard login."
                    read -p "Proceed with sc_auth enroll for $TARGET_USER? (y/N) " ans && [[ $ans =~ ^[Yy] ]] && sudo sc_auth enroll -u "$TARGET_USER" -c "$PIV_CERT_PATH" || echo "Skipped sc_auth enroll."
                else
                    echo "sc_auth tool not found. To enroll manually (if available on your macOS), run:"
                    echo "  sudo sc_auth enroll -u $TARGET_USER -c $PIV_CERT_PATH"
                fi
            else
                echo "To enroll this certificate for smartcard login (optional), run:"
                echo "  sudo sc_auth enroll -u $TARGET_USER -c $PIV_CERT_PATH"
            fi
        else
            echo "Specified PIV cert path not found: $PIV_CERT_PATH"
        fi
    fi

    cat <<PIVMSG
Manual next steps (recommended):

- Use ykman to generate a PIV key on the YubiKey or create a CSR to obtain a certificate from your CA.
  Examples (interactive guidance only):
    ykman piv keys generate 9a --algorithm RSA2048 public.pem
    # create CSR using openssl with the public key then have it signed by your CA
    # import certificate to YubiKey:
    ykman piv certificates import 9a cert.pem

- To allow macOS login / FileVault unlock using a PIV certificate, import the certificate into the
  System keychain and follow your organization's smartcard login enrollment process. This may
  require additional MDM or Directory Services configuration.

WARNING: Automating PIV enrollments is risky. Verify each step and keep recovery access.
PIVMSG
fi

# Ensure Yubico config dir exists and owned by user
    if [ "$INSTALL_PAM_U2F" = true ]; then
    echo "Creating Yubico config directory: $USER_HOME/.config/Yubico"
    sudo mkdir -p "$USER_HOME/.config/Yubico"
    sudo chown -R "$TARGET_USER" "$USER_HOME/.config/Yubico"

    if ! command -v pamu2fcfg >/dev/null 2>&1; then
        echo "pamu2fcfg not found. pam-u2f may not be installed correctly."
    else
        echo "Registering YubiKey for $TARGET_USER. When prompted, touch the YubiKey."
        # Ensure redirection happens as the target user so the file is owned correctly
        if sudo -u "$TARGET_USER" bash -c "pamu2fcfg > \"$AUTHFILE\""; then
            # secure the auth file
            sudo chmod 600 "$AUTHFILE" || true
            sudo chown "$TARGET_USER" "$AUTHFILE" || true
            echo "U2F authfile written to $AUTHFILE"
        else
            echo "pamu2fcfg failed or was cancelled. No authfile created."
        fi
    fi
fi

# Attempt to locate the pam_u2f module so we can reference a full path in PAM files
PAM_U2F_MODULE="pam_u2f.so"
if command -v brew >/dev/null 2>&1; then
    BREW_PREFIX=$(brew --prefix 2>/dev/null || true)
    if [ -n "$BREW_PREFIX" ]; then
        found=$(find "$BREW_PREFIX" -type f -name 'pam_u2f.so' 2>/dev/null | head -n1 || true)
        if [ -n "$found" ]; then
            PAM_U2F_MODULE="$found"
        fi
    fi
fi
if [ -z "$PAM_U2F_MODULE" ]; then
    PAM_U2F_MODULE="pam_u2f.so"
fi

# PAM modification logic: avoid overwriting original backup with already-modified file
modify_pam_service() {
    svc="$1"
    sudo_file="/etc/pam.d/$svc"
    if [ ! -f "$sudo_file" ]; then
        echo "PAM service file $sudo_file not found; skipping."
        return
    fi

    if grep -q "pam_u2f.so" "$sudo_file"; then
        echo "$sudo_file already references pam_u2f; skipping modification to avoid overwriting original backup."
        return
    fi

    BACKUP="$BACKUP_DIR/${svc}.bak.$TIMESTAMP"
    echo "Backing up $sudo_file -> $BACKUP"
    sudo cp "$sudo_file" "$BACKUP"

    tmpfile=$(mktemp)
    cat > "$tmpfile" <<EOF
# sudo: auth account password session
# Modified by install_yubikey_sudo.sh - original backed up at $BACKUP
auth       include        sudo_local

# 1) Require password
auth       required       pam_opendirectory.so

# 2) Require YubiKey (U2F)
auth       required       ${PAM_U2F_MODULE} authfile=$AUTHFILE cue

# Optional: remove smartcard unless you *also* want it required
# auth    required       pam_smartcard.so

account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
EOF

    echo "Writing modified PAM file to $sudo_file"
    sudo cp "$tmpfile" "$sudo_file"
    sudo chmod 644 "$sudo_file"
    rm -f "$tmpfile"
}

if [ "$MODIFY_PAM" = true ]; then
    for svc in "${services_to_modify[@]}"; do
        modify_pam_service "$svc"
    done
else
    echo "PAM modification not requested; skipping." 
fi

echo
echo "Done. IMPORTANT: Test in a NEW terminal session to avoid lockout."
echo "Example test:"
echo "  sudo -k && sudo -v && sudo ls /root"
echo
echo "Rollback example (restore original backup):"
echo "  sudo cp $BACKUP_DIR/<service>.bak.<timestamp> /etc/pam.d/<service>"

exit 0
