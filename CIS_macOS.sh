####################################################
# Description: CIS v8 automation for macOS
# Version: 0.2
# Author: jnqpblc
# Original Author: ICTrust
# LICENSE: MIT
####################################################

# Enable debugging by uncommenting the line bellow
## Early --debug support: if --debug or -d present anywhere in the CLI args, enable shell debugging now
for _arg in "$@"; do
    case "$_arg" in
        --debug|-d)
            set -x
            DEBUG=true
            break
            ;;
    esac
done

#set -x



# Variables
## Organisation info
org_contact="security@yourorg.example"
ntp="time.apple.com"
timezone="America/New_York"

## Messages 
login_screen_msg="If you found this laptop please contact $org_contact.\nA reward may be provided."
login_window_banner="* * * * * * * * * * W A R N I N G * * * * * * * * * *\nUNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED\nYou must have explicit, authorized permission to access or configure this device. Unauthorized attempts and actions to access or use this system may result in civil and/or criminal penalties. All activities performed on this device are logged and monitored.\n* * * * * * * * * * * * * * * * * * * * * * * *"



# Printing
RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_success() {
    printf "${GREEN}$1 ${NC}\n"
}

print_info() {
    printf "${BLUE}[INFO] $1 ${NC}\n"
}

print_fail() {
    printf "${RED}[ERROR] $1 ${NC}\n"
}


print_warn() {
    printf "${RED}[WARNING] $1 ${NC}\n"
}

# Helper to run systemsetup commands with captured output and cleaner messages
run_systemsetup() {
    output=$(sudo "$@" 2>&1)
    rc=$?
    # remove noisy internal Error:-99 lines if present
    filtered=$(printf "%s\n" "$output" | sed '/Error:-99/d')
    if [ $rc -ne 0 ]; then
        print_fail "Command failed: $*"
        if [[ -n "$filtered" ]]; then
            print_fail "$filtered"
        fi
        return $rc
    fi
    if [[ -n "$filtered" ]]; then
        print_warn "$filtered"
    fi
    return 0
}

# Validate timezone against system list
is_valid_timezone() {
    if systemsetup -listtimezones 2>/dev/null | grep -Fxq "$1"; then
        return 0
    fi
    return 1
}

# Check if Terminal has Full Disk Access for 'All Files'. If not, open Settings and exit.
check_terminal_full_disk_access() {
    bundle="com.apple.Terminal"
    user_to_check="${SUDO_USER:-$USER}"
    user_home=$(eval echo "~$user_to_check")
    db_path="$user_home/Library/Application Support/com.apple.TCC/TCC.db"

    if ! command -v sqlite3 >/dev/null 2>&1; then
        print_warn "Cannot check TCC database (sqlite3 not found)."
        print_warn "Please open System Settings -> Privacy & Security -> Full Disk Access and grant Terminal, then re-run the script."
        open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" >/dev/null 2>&1 || open -b com.apple.systempreferences >/dev/null 2>&1
        exit 1
    fi

    # Helper to run sqlite3 as the target user if needed
    run_sqlite() {
        sql="$1"
        if [ "$user_to_check" != "$(whoami)" ]; then
            sudo -u "$user_to_check" sqlite3 "$db_path" "$sql" 2>/dev/null || true
        else
            sqlite3 "$db_path" "$sql" 2>/dev/null || true
        fi
    }

    if [ -f "$db_path" ]; then
        # try several query patterns to match different macOS TCC schemas/clients
        clients=("%com.apple.Terminal%" "%com.apple.terminal%" "%Terminal%" "%Terminal.app%" "%/Terminal.app%" "%/Utilities/Terminal.app%")
        services=("kTCCServiceSystemPolicyAllFiles" "%AllFiles%" "%SystemPolicyAllFiles%")
        for svc in "${services[@]}"; do
            for cl in "${clients[@]}"; do
                # try selecting allowed column
                out=$(run_sqlite "SELECT allowed FROM access WHERE service='$svc' AND client LIKE '$cl' LIMIT 1;")
                if [[ -n "$out" ]]; then
                    out_trim=$(echo "$out" | tr -d '\r\n ')
                    if [[ "$out_trim" == "1" ]]; then
                        return 0
                    fi
                fi
                # try auth_value column if present
                out2=$(run_sqlite "SELECT auth_value FROM access WHERE service='$svc' AND client LIKE '$cl' LIMIT 1;")
                if [[ -n "$out2" ]]; then
                    out2_trim=$(echo "$out2" | tr -d '\r\n ')
                    if [[ "$out2_trim" == "1" ]]; then
                        return 0
                    fi
                fi
                # try generic row presence
                out3=$(run_sqlite "SELECT client,allowed FROM access WHERE service='$svc' AND client LIKE '$cl' LIMIT 1;")
                if [[ -n "$out3" ]]; then
                    # if allowed appears as 1 in the row
                    if echo "$out3" | grep -q "1"; then
                        return 0
                    fi
                fi
            done
        done
    fi

    # also try system-wide TCC DB (different macOS versions)
    system_db="/Library/Application Support/com.apple.TCC/TCC.db"
    if [ -f "$system_db" ]; then
        if [ "$user_to_check" != "$(whoami)" ]; then
            sudo -u "$user_to_check" sqlite3 "$system_db" "SELECT allowed FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND client LIKE '%Terminal%' LIMIT 1;" 2>/dev/null | grep -q "1" && return 0 || true
        else
            sqlite3 "$system_db" "SELECT allowed FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND client LIKE '%Terminal%' LIMIT 1;" 2>/dev/null | grep -q "1" && return 0 || true
        fi
    fi

    print_warn "Terminal does not appear to have Full Disk Access (check may not be accurate on this macOS)."
    print_warn "Opening System Settings -> Privacy & Security -> Full Disk Access. Add Terminal, then re-run this script."
    open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" >/dev/null 2>&1 || open -b com.apple.systempreferences >/dev/null 2>&1
    exit 1
}

# CLI flags defaults
AUTO_YES=false
TZ_PROVIDED=false
EMAIL_PROVIDED=false
NTP_PROVIDED=false
SKIP_FDA_CHECK=false
DEBUG=false

# Parse CLI arguments (allow overriding timezone and auto-yes)
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--timezone)
            if [[ -n "$2" ]]; then
                timezone="$2"
                TZ_PROVIDED=true
                shift 2
            else
                echo "Error: $1 requires an argument"
                exit 1
            fi
            ;;
        --timezone=*)
            timezone="${1#*=}"
            TZ_PROVIDED=true
            shift
            ;;
        -y|--yes)
            AUTO_YES=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [-t TIMEZONE|--timezone=TIMEZONE] [-n NTP|--ntp=NTP] [-e EMAIL|--email=EMAIL] [-y|--yes] [--skip-fda-check] [--debug|-d]"
            echo "Example: $0 --timezone=America/Los_Angeles --ntp=time.apple.com --email=help@example.com --yes --debug"
            exit 0
            ;;
        --debug|-d)
            DEBUG=true
            shift
            ;;
        --skip-fda-check)
            SKIP_FDA_CHECK=true
            shift
            ;;
        -n|--ntp)
            if [[ -n "$2" ]]; then
                ntp="$2"
                NTP_PROVIDED=true
                shift 2
            else
                echo "Error: $1 requires an argument"
                exit 1
            fi
            ;;
        --ntp=*)
            ntp="${1#*=}"
            NTP_PROVIDED=true
            shift
            ;;
        -e|--email)
            if [[ -n "$2" ]]; then
                org_contact="$2"
                EMAIL_PROVIDED=true
                shift 2
            else
                echo "Error: $1 requires an argument"
                exit 1
            fi
            ;;
        --email=*)
            org_contact="${1#*=}"
            EMAIL_PROVIDED=true
            shift
            ;;
        *)
            break
            ;;
    esac
done

# List of current users
users_list=$(dscacheutil -q user | grep -A 3 -B 2 -e uid:\ 5'[0-9][0-9]' | grep name | cut -d' ' -f2)

# If email not provided on CLI, prompt now
if [ "$EMAIL_PROVIDED" != "true" ]; then
    read -p "Contact email to display on lost device [$org_contact]: " email_input
    if [[ -n "$email_input" ]]; then
        org_contact="$email_input"
    fi
fi

# Use default NTP server unless overridden via CLI
if [ "$NTP_PROVIDED" = "true" ]; then
    print_info "Using NTP server from CLI: $ntp"
else
    print_info "Using default NTP server: $ntp"
fi

# Check Terminal Full Disk Access unless explicitly skipped
if [ "$SKIP_FDA_CHECK" != "true" ]; then
    check_terminal_full_disk_access
else
    print_warn "Skipping Full Disk Access check ( --skip-fda-check )"
fi

################################################
# 1.1 Verify all Apple-provided software is current
################################################
print_info "Check for system updates"
if softwareupdate -l 2>&1 | grep -qE "No new software available\.|No updates are available"; then
    print_success "No software updates available"
else
    print_fail "System updates are available"
    if [ "$AUTO_YES" = "true" ]; then
        print_info "Auto-yes provided; installing updates"
        sudo softwareupdate -i -a
    else
        read -p "Do you wish to install the updates? (y/n) " yn
        case $yn in
            [Yy]* ) sudo softwareupdate -i -a ;;
            [Nn]* ) ;;
            * ) echo "Please answer yes or no." ;;
        esac
    fi
fi

################################################
# 1.2 Enable Auto Update
################################################
print_info "Enable automatic updates"
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true

################################################
# 1.3 Enable Download new updates when available
################################################
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true


################################################
# 1.4 Enable app update installs 
################################################
print_info "Enable Download new updates when available"
sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true


################################################
# 1.4 Enable system data files and security updates install 
################################################
print_info "Enable system data files and security updates install"
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true


################################################
# 1.4 Enable macOS update installs
################################################
print_info "Enable macOS update installs"
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true

################################################
# 2 System Preferences
################################################

################################################
# 2.1 Bluetooth
################################################
# Skipped

################################################
# 2.2.1 Enable "Set time and date automatically"
################################################
if [ "$TZ_PROVIDED" != "true" ]; then
    while true; do
        read -p "Timezone to configure [$timezone]: " tz_input
        if [[ -z "$tz_input" ]]; then
            tz_input="$timezone"
        fi
        if is_valid_timezone "$tz_input"; then
            timezone="$tz_input"
            break
        else
            echo "Invalid timezone: $tz_input"
            echo "Run 'systemsetup -listtimezones' to see valid values."
        fi
    done
fi

run_systemsetup systemsetup -setnetworktimeserver "$ntp"
print_info "Enable automatic date and time: $ntp"
print_info "Configuring timezone: $timezone"
run_systemsetup systemsetup -settimezone "$timezone"
run_systemsetup systemsetup -setusingnetworktime on

################################################
# 2.2.2 Ensure time set is within appropriate limits
################################################
# TO-DO

################################################
# 2.3 Desktop & Screen Saver
################################################
################################################
# 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver
################################################
print_info "Set inactivity interval to 10 minutes"
sudo defaults -currentHost write com.apple.screensaver idleTime -int 600 2> /dev/null

################################################
# 2.3.2 Secure screen saver corners
################################################
# By default (on macos 12.x) the value does not exist which is compliant

################################################
# 2.4.1 Disable Remote Apple Events
################################################
print_info "Disable Remote Apple Events"
sudo systemsetup -setremoteappleevents off 2> /dev/null

################################################
# 2.4.2 Disable Internet Sharing
################################################
print_info "Disable Internet Sharing"
sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict Enabled -int 0 2> /dev/null


################################################
# 2.4.3 Disable Screen Sharing
################################################
print_info "Disable screen sharing"
sudo launchctl disable system/com.apple.screensharing 2> /dev/null 

################################################
# 2.4.4 Disable Printer Sharing 
################################################
print_info "Disable printer sharing"
sudo cupsctl --no-share-printers 2> /dev/null  

################################################
# 2.4.5 Disable Remote Login 
################################################
print_info "Disable remote login"
print_warn "WARNING: If you disable remote login you may lose your current connection."
print_warn "Do you really want to turn remote login off? If you do, you will lose this connection and can only turn it back on locally at the device."
if [ "$AUTO_YES" = "true" ]; then
    print_info "Auto-yes provided; disabling remote login"
    printf "yes\n" | sudo systemsetup -setremotelogin off 2> /dev/null || print_warn "Failed to disable remote login"
else
    read -p "Disable remote login? (y/n) " yn
    case $yn in
        [Yy]* ) printf "yes\n" | sudo systemsetup -setremotelogin off 2> /dev/null || print_warn "Failed to disable remote login" ;;
        [Nn]* ) print_info "Skipping disabling remote login" ;;
        * ) echo "Please answer y or n." ;;
    esac
fi

################################################
# 2.4.6 Disable DVD or CD Sharing 
################################################
print_info "Disable DVD or CD Sharing"
sudo launchctl disable system/com.apple.ODSAgent 2> /dev/null

################################################
# 2.4.7 Disable Bluetooth Sharing
################################################
print_info "Disable Bluetooth Sharing for all users"
for user in $users_list; do
    sudo -u "$user" defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false 2> /dev/null
done

################################################
# 2.4.8 Disable File Sharing
################################################
print_info "Disable file sharing"
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist 2> /dev/null

################################################
# 2.4.9 Disable Remote Management
################################################
print_info "Disable remote management"
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources /kickstart -deactivate -stop 2> /dev/null

################################################
# 2.4.10 Disable Content Caching
################################################
print_info "Disable content caching"
sudo AssetCacheManagerUtil deactivate 2> /dev/null

################################################
# 2.4.11 Disable Media Sharing
################################################
print_info "Disable Media Sharing"
for user in $users_list; do
    sudo -u "$user" defaults write com.apple.amp.mediasharingd home-sharing-enabled -int 0 2> /dev/null
done

################################################
# 2.4.12 Ensure AirDrop Is Disabled
################################################
print_info "Disable AirDrop"
for user in $users_list; do
    sudo -u "$user" defaults write com.apple.NetworkBrowser DisableAirDrop -bool true 2> /dev/null
done

################################################
# 2.5 Security & Privacy
################################################
################################################
# 2.5.1 Encryption
################################################
################################################
# 2.5.1.1 Enable FileVault
################################################
print_info "Check if FileVault is enabled"
filevault_status=$(sudo fdesetup status)
if [[ $filevault_status == "FileVault is On." ]]; then
    print_success "FileVault is enabled"
else 
    print_fail "FileVault is disabled"
fi

################################################
# 2.5.2 Firewall 
################################################
################################################
# 2.5.2.1 Enable Gatekeeper
################################################
print_info "Enable Gatekeeper"
sudo spctl --master-enable 2> /dev/null

################################################
# 2.5.2.1 Enable Firewall
################################################
print_info "Enable Firewall"
sudo defaults write /Library/Preferences/com.apple.alf globalstate -int 2 2> /dev/null
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

################################################
# 2.5.2.3 Enable Firewall Stealth Mode
################################################
print_info "Enable Stealth Mode"
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on


################################################
# 2.5.3 Enable Location Services
################################################
# Skipped 

################################################
# 2.5.5 Disable sending diagnostic and usage data to Apple
################################################
print_info "Disable sending diagnostic and usage data to Apple"
sudo defaults write /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit -bool false 2> /dev/null
sudo chmod 644 /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist 2> /dev/null
sudo chgrp admin /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist 2> /dev/null

################################################
# 2.5.6 Limit Ad tracking and personalized Ads
################################################
print_info "Limit Ad tracking and personalized Ads"
for user in $users_list; do
    sudo -u "$user" defaults -currentHost write /Users/"$user"/Library/Preferences/com.apple.Adlib.plist allowApplePersonalizedAdvertising -bool false 2> /dev/null
done

################################################
# 2.6.1 iCloud configuration
################################################
# TO-DO 

################################################
# 2.7 Time Machine
################################################
# TO-DO

################################################
# 2.8 Disable Wake for network access 
################################################
print_info "Disable Wake for network access"
sudo pmset -a womp 0 2> /dev/null 

################################################
# 2.9 Disable Power Nap
################################################
print_info "Disable Power Nap"
sudo pmset -a powernap 0

################################################
# 2.10 Enable Secure Keyboard Entry in terminal.app
################################################
print_info "Enable Secure Keyboard Entry in terminal.app"
printf '%s\n' "$users_list" | while IFS= read -r user; do
    sudo -u "$user" defaults write -app Terminal SecureKeyboardEntry -bool true 2> /dev/null
done

################################################
# 2.11 Ensure EFI version is valid and being regularly checked
################################################
# TO-DO 

################################################
# 2.12 Automatic Actions for Optical Media 
################################################
# TO-DO 

################################################
# 2.13 Review Siri Settings
################################################
print_info "Disable Siri"
for user in $users_list; do
    sudo -u "$user" defaults write com.apple.assistant.support.plist 'Assistant Enabled' -bool false 2> /dev/null
    sudo -u "$user" defaults write com.apple.Siri.plist LockscreenEnabled -bool false 2> /dev/null
    sudo -u "$user" defaults write com.apple.Siri.plist StatusMenuVisible -bool false 2> /dev/null
    sudo -u "$user" defaults write com.apple.Siri.plist VoiceTriggerUserEnabled -bool false 2> /dev/null
done
 
# Restart the Windows Server and clear the caches
sudo killall -HUP cfprefsd
sudo killall SystemUIServer

################################################
# 3 Logging and Auditing
################################################
################################################
# 3.1 Enable security auditing 
################################################
print_info "Enable security auditing "
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2> /dev/null

################################################
# 3.2 Configure Security Auditing Flags per local organizational requirements
################################################
print_info "Set auditing flags to 'all'"
if [ -f /etc/security/audit_control ]; then
    sudo sed -i.bu "s/^flags:.*/flags:all/g" /etc/security/audit_control 2> /dev/null || print_warn "Failed to update /etc/security/audit_control"
else
    print_warn "/etc/security/audit_control not found; skipping"
fi

################################################
# 3.3 Retain install.log for 365 or more days with no maximum sizes
################################################
print_info "Retain install.log for 365 days"
if [ -f /etc/asl/com.apple.install ]; then
    sudo sed -i.bu '$s/$/ ttl=365/' /etc/asl/com.apple.install || print_warn "Failed to update /etc/asl/com.apple.install"
    print_info "Set maximum size to 1G"
    sudo sed -i.bu 's/all_max=[0-9]*[mMgG]/all_max=1G/g' /etc/asl/com.apple.install || print_warn "Failed to set size in /etc/asl/com.apple.install"
else
    print_warn "/etc/asl/com.apple.install not found; skipping"
fi

################################################
# 3.4 Ensure security auditing retention
################################################
print_info "Set audit records expiration to 1 gigabyte"
if [ -f /etc/security/audit_control ]; then
    sudo sed -i.bu "s/^expire-after:.*/expire-after:1G/g" /etc/security/audit_control || print_warn "Failed to set expire-after in /etc/security/audit_control"
else
    print_warn "/etc/security/audit_control not found; skipping"
fi

################################################
# 3.5 Control access to audit records
################################################
print_info "Set the audit records to the root user and wheel group"
if [ -f /etc/security/audit_control ]; then
    sudo chown -R root:wheel /etc/security/audit_control 2> /dev/null
    sudo chmod -R -o-rw /etc/security/audit_control 2> /dev/null
else
    print_warn "/etc/security/audit_control not found; skipping ownership and perms"
fi
if [ -d /var/audit ]; then
    sudo chown -R root:wheel /var/audit/ 2> /dev/null
    sudo chmod -R -o-rw /var/audit/ 2> /dev/null
else
    print_warn "/var/audit not found; skipping ownership and perms"
fi

################################################
# 3.6 Ensure Firewall is configured to log
################################################
print_info "Enable firewall logging mode"
SF=/usr/libexec/ApplicationFirewall/socketfilterfw
if "$SF" --help 2>&1 | grep -qi "setloggingmode"; then
    sudo "$SF" --setloggingmode on
else
    print_warn "socketfilterfw does not support --setloggingmode on this macOS; skipping"
fi

################################################
# 3.7 Software Inventory Considerations
################################################
# TO-DO 


################################################
# 4 Network Configurations
################################################
################################################
# 4.1 Disable Bonjour advertising service
################################################
print_info "Enable firewall logging mode"
sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true

################################################
# 4.2 Enable "Show Wi-Fi status in menu bar"
################################################
print_info "Enable 'Show Wi-Fi status in menu bar' for all users" 
for user in $users_list; do
    sudo -u "$user" defaults -currentHost write com.apple.controlcenter.plist WiFi -int 18
done

################################################
# 4.3 Create network specific locations
################################################
# Skipped 

################################################
# 4.4 Ensure http server is not running
################################################
print_info "Disabling and shuting down http server"
if command -v apachectl >/dev/null 2>&1; then
    sudo apachectl stop || print_warn "apachectl stop failed"
else
    print_warn "apachectl not present; skipping"
fi
APPLAUNCH=/System/Library/LaunchDaemons/org.apache.httpd
if [ -e "$APPLAUNCH" ]; then
    if [ -w "$APPLAUNCH" ] || [ $(id -u) -eq 0 ]; then
        sudo defaults write "$APPLAUNCH" Disabled -bool true || print_warn "Failed to write Disabled to $APPLAUNCH"
    else
        print_warn "$APPLAUNCH exists but is not writable; skipping defaults write"
    fi
else
    print_warn "$APPLAUNCH not found; skipping"
fi


################################################
# 4.5 Ensure nfs server is not running
################################################
print_info "Disabling NFS server"
sudo launchctl disable system/com.apple.nfsd 2> /dev/null || print_warn "Failed to disable NFS server"
if [ -f /etc/exports ]; then
    sudo rm /etc/exports || print_warn "Failed to remove /etc/exports"
else
    print_warn "/etc/exports not found; skipping"
fi

################################################
# 4.6 Review Wi-Fi Settings
################################################
# Skipped

################################################
# 5 System Access, Authentication and Authorization
################################################
################################################
# 5.1 File System Permissions and Access Controls
################################################

################################################
# 5.1.1 Secure Home Folders 
################################################
print_info "Securing home folders"
for user in $users_list; do
    sudo chmod -R og-rwx /Users/"$user" 2> /dev/null
done
 
################################################
# 5.1.2 Check System Wide Applications for appropriate permissions
################################################
# Skipped 

################################################
# 5.1.3 Check System folder for world writable files
################################################
# Skipped 

################################################
# 5.1.4 Check Library folder for world writable files
################################################
# TO-DO 

################################################
# 5.2 Password Management
################################################
################################################
# 5.2.1 Configure account lockout threshold
###############################################
print_info "Settings maximum failed login attempts to 5 before locking the account"
sudo pwpolicy -n /Local/Default -setglobalpolicy "maxFailedLoginAttempts=5"

################################################
# 5.2.2 Set a minimum password length 
###############################################
print_info "Settings minimum password length to 15"
sudo pwpolicy -n /Local/Default -setglobalpolicy "minChars=15"

################################################
# 5.2.3 Complex passwords must contain an Alphabetic Character
###############################################
print_info "Set password policy: must contain an Alphabetic Character"
sudo pwpolicy -n /Local/Default -setglobalpolicy "requiresAlpha=1"

################################################
# 5.2.4 Complex passwords must contain a Numeric Character 
###############################################
print_info "Set password policy: must contain an Alphabetic Character"
sudo pwpolicy -n /Local/Default -setglobalpolicy "requiresAlpha=1"

################################################
# 5.2.4 Complex passwords must contain a Numeric Character 
###############################################
print_info "Set password policy: must contain an Numeric Character"
sudo pwpolicy -n /Local/Default -setglobalpolicy "requiresNumeric=1"

################################################
# 5.2.5 Complex passwords must contain a Special Character
###############################################
print_info "Set password policy: must contain an Special Character"
sudo pwpolicy -n /Local/Default -setglobalpolicy "requiresSymbol=1"

################################################
# 5.2.6 Complex passwords must contain uppercase and lowercase letters
###############################################
print_info "Set password policy: must contain uppercase and lowercase letters"
sudo pwpolicy -n /Local/Default -setglobalpolicy "requiresMixedCase=1"

################################################
# 5.2.7 Password Age
###############################################
print_info "Set password expiration to 365 days"
sudo pwpolicy -n /Local/Default -setglobalpolicy "maxMinutesUntilChangePassword=525600"

################################################
# 5.2.8 Password History 
###############################################
print_info "Set password policy: must to be different from at least the last 15 passwords"
sudo pwpolicy -n /Local/Default -setglobalpolicy "usingHistory=15"

################################################
# 5.3 Reduce the sudo timeout period
################################################ 
print_info "Reduce sudo timeout period to 0"
timestamp_exist=$(sudo grep "timestamp_timeout" /etc/sudoers)
if [[ $timestamp_exist ]]; then
   sudo sed -i.bu "s/timestamp_timeout=[0-9]*/timestamp_timeout=0/g"  /etc/sudoers
else
    echo "Defaults timestamp_timeout=0" | sudo tee -a /etc/sudoers
fi

################################################
# 5.4 Automatically lock the login keychain for inactivity
################################################
print_info "Set automatic keychain lock after 6 hours"
printf '%s\n' "$users_list" | while IFS= read -r user; do
    print_info "User: $user"
    # Prompt silently for keychain password and use it to unlock the keychain
    read -s -p "Password to unlock /Users/$user/Library/Keychains/login.keychain: " _kc_pw
    echo
    if [[ -n "$_kc_pw" ]]; then
        sudo -u "$user" security unlock-keychain -p "$_kc_pw" "/Users/$user/Library/Keychains/login.keychain" 2> /dev/null || print_warn "Failed to unlock keychain for $user"
        sudo -u "$user" security set-keychain-settings -t 21600 "/Users/$user/Library/Keychains/login.keychain"
        # clear secret
        _kc_pw=''
        unset _kc_pw
    else
        print_warn "No password entered; skipping keychain unlock for $user"
    fi
done

################################################
# 5.5 Use a separate timestamp for each user/tty comboy
################################################
# TO-DO 

################################################
# 5.6 Ensure login keychain is locked when the computer sleeps
################################################
print_info "Lock keychain when the computer sleeps"
printf '%s\n' "$users_list" | while IFS= read -r user; do
    print_info "User: $user"
    read -s -p "Password to unlock /Users/$user/Library/Keychains/login.keychain: " _kc_pw
    echo
    if [[ -n "$_kc_pw" ]]; then
        sudo -u "$user" security unlock-keychain -p "$_kc_pw" "/Users/$user/Library/Keychains/login.keychain" 2> /dev/null || print_warn "Failed to unlock keychain for $user"
        sudo -u "$user" security set-keychain-settings -l "/Users/$user/Library/Keychains/login.keychain"
        _kc_pw=''
        unset _kc_pw
    else
        print_warn "No password entered; skipping keychain unlock for $user"
    fi
done

################################################
# 5.7 Do not enable the "root" account
################################################
# Skipped

################################################
# 5.8 Disable automatic login
################################################
print_info "Disable automatic login"
sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser

################################################
# 5.9 Require a password to wake the computer from sleep or screen saver
################################################
print_info "Enable require password to wake the computer from sleep or screen saver"
for user in $users_list; do
    sudo -u "$user" defaults write /Users/"$user"/Library/Preferences/com.apple.screensaver askForPassword -int 1
done

################################################
# 5.10 Ensure system is set to hibernate
################################################
print_info "Set the hibernate delays and to ensure the FileVault keys are set to be destroyed on standby"
sudo pmset -a standbydelayhigh 600
sudo pmset -a standbydelaylow 600
sudo pmset -a highstandbythreshold 90
sudo pmset -a destroyfvkeyonstandby 1

################################################
# 5.11 Require an administrator password to access system-wide preferences
################################################
print_info "Enable administrator password requirement to access system-wide preferences"
security authorizationdb read system.preferences > /tmp/system.preferences.plist
/usr/libexec/PlistBuddy -c "Set :shared false" /tmp/system.preferences.plist
security authorizationdb write system.preferences < /tmp/system.preferences.plist

################################################
# 5.12 Ensure an administrator account cannot login to another user's active and locked session
################################################
print_info "Ensure an administrator account cannot login to another user's active and locked session"
sudo security authorizationdb write system.login.screensaver use-login-window-ui

################################################
# 5.13 Create a custom message for the Login Screen
################################################ 
login_screen_msg="If you found this laptop please contact $org_contact.\nA reward may be provided."
print_info "Add login screen message: $login_screen_msg"
sudo defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText "$login_screen_msg"

################################################
# 5.14 Create a Login window banner
################################################
print_info "Add login window banner"
printf '%b\n' "$login_window_banner" | sudo tee /Library/Security/PolicyBanner.txt
sudo chmod 755 "/Library/Security/PolicyBanner."*  2> /dev/null

# If FileVault is enabled on APFS, update the Preboot volume so the banner is propagated
filevault_status=$(sudo fdesetup status 2>/dev/null || true)
if diskutil info / 2>/dev/null | grep -qi "APFS"; then
    if echo "$filevault_status" | grep -qi "FileVault is On\."; then
        print_info "FileVault is enabled; updating APFS Preboot to apply banner"
        if sudo diskutil apfs updatePreboot / >/dev/null 2>&1; then
            print_success "APFS Preboot updated successfully"
        else
            print_warn "Failed to update APFS Preboot. Run 'sudo diskutil apfs updatePreboot /' manually or reboot."
        fi
    else
        print_info "APFS detected but FileVault not enabled; preboot update not required"
    fi
fi

################################################
# 5.15 Do not enter a password-related hint
################################################
print_info "Delete password-related hint of all users if exist"
for user in $users_list; do
    sudo dscl . -delete /Users/$user hint
done

################################################
# 5.16 Disable Fast User Switching
################################################
print_info "Disable fast user switching"
sudo defaults write /Library/Preferences/.GlobalPreferences MultipleSessionEnabled -bool false

################################################
# 5.17 Secure individual keychains and items
################################################
# TO-DO

################################################
# 5.18 System Integrity Protection status
################################################
print_info "Check System Integrity Protection (SIP) status"
csr_status=$(/usr/bin/csrutil status 2>&1 || true)
if echo "$csr_status" | grep -qi "enabled"; then
    print_success "System Integrity Protection is enabled"
else
    print_warn "System Integrity Protection is disabled. To enable SIP, reboot into Recovery and run 'csrutil enable'. Skipping."
fi

################################################
# 5.19 Sealed System Volume (authenticated-root)
################################################
print_info "Check Sealed System Volume (authenticated-root) status"
if echo "$csr_status" | grep -qi "authenticated-root"; then
    print_success "Authenticated-root appears enabled"
else
    print_warn "Authenticated-root may be disabled. To enable, reboot into Recovery and run 'csrutil enable authenticated-root'. Skipping."
fi

################################################
# 5.20 Enable Library Validation
################################################
print_info "Enable library validation"
sudo defaults write /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation -bool false

################################################
# 5.21 Disable core dumps and apply safe sysctl hardening
################################################
print_info "Apply sysctl hardening settings"
sysctl_file="/etc/sysctl.conf"

upsert_sysctl() {
    key="$1"
    value="$2"
    # replace existing or append
    if [ -f "$sysctl_file" ] && sudo grep -q "^${key}=" "$sysctl_file" 2>/dev/null; then
        sudo sed -i.bu "s/^${key}=.*/${key}=${value}/" "$sysctl_file" 2>/dev/null || print_warn "Failed to update $key in $sysctl_file"
    else
        echo "${key}=${value}" | sudo tee -a "$sysctl_file" >/dev/null || print_warn "Failed to append $key to $sysctl_file"
    fi
    # attempt to apply at runtime
    if sudo sysctl -w "${key}=${value}" >/dev/null 2>&1; then
        print_success "Applied ${key}=${value} at runtime"
    else
        print_warn "Could not apply ${key}=${value} at runtime (may require reboot or SIP/authenticated-root disabled)"
    fi
}

print_info "Disabling core dumps (kern.coredump=0)"
upsert_sysctl "kern.coredump" "0"

# Additional safe sysctl hardening recommended by CIS (non-disruptive defaults)
print_info "Ensure IP forwarding is disabled"
upsert_sysctl "net.inet.ip.forwarding" "0"
upsert_sysctl "net.inet6.ip6.forwarding" "0"

print_warn "If System Integrity Protection (SIP) or authenticated-root is enabled, changes to /etc may be restricted."
print_warn "To make persistent changes on a system with authenticated-root, temporarily disable authenticated-root in Recovery, make changes, then re-enable authenticated-root and SIP."


################################################
# 6 User Accounts and Environment
# 6.1 Accounts Preferences Action Items
# 6.1.1 Display login window as name and password
################################################
print_info "Display login window as name and password"
sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true

################################################
# 6.1.2 Disable "Show password hints"
################################################
print_info "Disable 'Show password hints'"
sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0

################################################
# 6.1.3 Disable guest account login
################################################
print_info "Disable guest account login"
sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false

################################################
# 6.1.4 Disable "Allow guests to connect to shared folders"
################################################
print_info "Disable 'Allow guests to connect to shared folders'"
sudo defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false
sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool false

################################################
# 6.1.5 Remove Guest home folder 
################################################
print_info "Remove Guest home folder if exist"
sudo rm -R /Users/Guest 2> /dev/null

################################################
# 6.2 Turn on filename extensions
################################################
print_info "Turn on filename extensions"
for user in $users_list; do
    sudo -u "$user" defaults write /Users/"$user"/Library/Preferences/.GlobalPreferences.plist AppleShowAllExtensions -bool true
done

################################################
# 6.3 Disable the automatic run of safe files in Safari
################################################
print_info "Disable the automatic run of safe files in Safari"
for user in $users_list; do
    sudo -u "$user" defaults write /Users/$user/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari AutoOpenSafeDownloads -bool false
done

# Disable debugging
set +x
