#!/bin/bash
# sentry - safe and effective protection against bruteforce attacks
# Ported to bash from Perl, using SQLite instead of DBM
# Original author: Matt Simerson (@msimerson)

set -e

VERSION='2.00'

# Configuration - adjust these to taste
ROOT_DIR="${ROOT_DIR:-/var/db/sentry}"
ADD_TO_TCPWRAPPERS="${ADD_TO_TCPWRAPPERS:-1}"
ADD_TO_PF="${ADD_TO_PF:-1}"
ADD_TO_IPFW="${ADD_TO_IPFW:-0}"
ADD_TO_IPTABLES="${ADD_TO_IPTABLES:-0}"
FIREWALL_TABLE="${FIREWALL_TABLE:-sentry_blacklist}"
EXPIRE_BLOCK_DAYS="${EXPIRE_BLOCK_DAYS:-90}"  # 0 to never expire
PROTECT_FTP="${PROTECT_FTP:-1}"
PROTECT_SMTP="${PROTECT_SMTP:-0}"
PROTECT_MUA="${PROTECT_MUA:-1}"  # dovecot POP3 & IMAP
DL_URL='https://raw.githubusercontent.com/msimerson/sentry/master/sentry.sh'

# Global variables
IP=""
VERBOSE=0
DB_PATH=""
TCPD_DENYLIST=""

# IP record
SEEN=0
WHITE=0
BLACK=0

# Function to print verbose messages
log_verbose() {
    if [ "$VERBOSE" -eq 1 ]; then
        echo "$@"
    fi
}

# Function to get OS name
get_os() {
    uname -s | tr '[:upper:]' '[:lower:]'
}

# Function to get denylist file location
get_denylist_file() {
    local os=$(get_os)
    if [[ "$os" =~ (linux|freebsd) ]]; then
        echo "$ROOT_DIR/hosts.deny"
    else
        echo "/etc/hosts.deny"
    fi
}

# Function to validate IPv4 address
is_valid_ipv4() {
    local ip=$1
    local IFS='.'
    local -a octets=($ip)
    
    # Check if we have exactly 4 octets
    if [ ${#octets[@]} -ne 4 ]; then
        return 1
    fi
    
    # Check if first octet is less than 1
    if [ "${octets[0]}" -lt 1 ]; then
        return 1
    fi
    
    # Check if all octets are 255
    local all_255=1
    for octet in "${octets[@]}"; do
        if [ "$octet" -ne 255 ]; then
            all_255=0
            break
        fi
    done
    if [ "$all_255" -eq 1 ]; then
        return 1
    fi
    
    # Validate each octet
    for octet in "${octets[@]}"; do
        if ! [[ "$octet" =~ ^[0-9]+$ ]] || [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
            return 1
        fi
    done
    
    log_verbose "ip $ip is valid"
    return 0
}

# Function to validate IP address
is_valid_ip() {
    if [ -z "$IP" ]; then
        return 1
    fi
    
    # Handle IPv6 notation like ::ffff:208.75.177.98
    if [[ "$IP" =~ ^::ffff: ]]; then
        IP="${IP##*:}"
    fi
    
    if is_valid_ipv4 "$IP"; then
        return 0
    fi
    
    # TODO: Add IPv6 support
    return 1
}

# Function to convert IP to integer key
ip_to_key() {
    local ip=$1
    local IFS='.'
    local -a octets=($ip)
    local key=$(( (${octets[0]} << 24) + (${octets[1]} << 16) + (${octets[2]} << 8) + ${octets[3]} ))
    echo "$key"
}

# Function to initialize database
init_db() {
    # Create root directory if needed
    if [ ! -d "$ROOT_DIR" ]; then
        log_verbose "creating ssh sentry root at $ROOT_DIR"
        mkdir -p "$ROOT_DIR" || { echo "unable to create $ROOT_DIR" >&2; exit 1; }
        chmod 750 "$ROOT_DIR"
    fi
    
    DB_PATH="$ROOT_DIR/sentry.db"
    
    # Create database and table if needed
    sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS ip_records (
        key INTEGER PRIMARY KEY,
        ip TEXT NOT NULL,
        seen INTEGER DEFAULT 0,
        white INTEGER DEFAULT 0,
        black INTEGER DEFAULT 0
    );" || { echo "Failed to create database" >&2; exit 1; }
    
    TCPD_DENYLIST=$(get_denylist_file)
    
    log_verbose "using $DB_PATH as database"
}

# Function to load IP record from database
load_ip_record() {
    if [ -z "$IP" ]; then
        log_verbose "no IP, skip loading record"
        return
    fi
    
    local key=$(ip_to_key "$IP")
    local result=$(sqlite3 "$DB_PATH" "SELECT seen, white, black FROM ip_records WHERE key = $key;" 2>/dev/null)
    
    if [ -n "$result" ]; then
        IFS='|' read -r SEEN WHITE BLACK <<< "$result"
    else
        SEEN=0
        WHITE=0
        BLACK=0
    fi
    
    printf "%4d connections from %s (key: %s)\n" "$SEEN" "$IP" "$key"
    if [ "$WHITE" -ne 0 ]; then
        echo -e "\tand it is whitelisted"
    fi
    if [ "$BLACK" -ne 0 ]; then
        echo -e "\tand it is blacklisted"
    fi
}

# Function to save IP record to database
save_ip_record() {
    if [ -z "$IP" ]; then
        return
    fi
    
    local key=$(ip_to_key "$IP")
    sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO ip_records (key, ip, seen, white, black) 
                        VALUES ($key, '$IP', $SEEN, $WHITE, $BLACK);" 2>/dev/null
}

# Function to check if IP is whitelisted
is_whitelisted() {
    if [ "$WHITE" -eq 0 ]; then
        return 1
    fi
    log_verbose "is whitelisted"
    return 0
}

# Function to check if IP is blacklisted
is_blacklisted() {
    if [ "$BLACK" -eq 0 ]; then
        return 1
    fi
    
    log_verbose "is blacklisted"
    
    # Check if we should expire old blacklist entries
    if [ "$EXPIRE_BLOCK_DAYS" -eq 0 ]; then
        return 0
    fi
    
    local bl_ts=$BLACK
    local now=$(date +%s)
    local days_old=$(( (now - bl_ts) / 86400 ))
    
    if [ "$days_old" -gt "$EXPIRE_BLOCK_DAYS" ]; then
        do_unblacklist
    fi
    
    return 0
}

# Function to configure tcpwrappers
configure_tcpwrappers() {
    local is_setup=0
    
    for file in /etc/hosts.allow /etc/hosts.deny "$TCPD_DENYLIST"; do
        if [ -n "$file" ] && [ -f "$file" ] && [ -r "$file" ]; then
            if grep -q sentry "$file" 2>/dev/null; then
                is_setup=1
                break
            fi
        fi
    done
    
    if [ "$is_setup" -eq 1 ]; then
        return 0
    fi
    
    local script_loc="$ROOT_DIR/sentry.sh"
    local spawn="sshd : ALL : spawn $script_loc --connect --ip=%a : allow"
    
    local os=$(get_os)
    if [[ "$os" =~ (freebsd|linux) ]]; then
        echo ""
        echo "NOTICE: you need to add these lines near the top of your /etc/hosts.allow file"
        echo ""
        echo "sshd : $TCPD_DENYLIST : deny"
        echo "$spawn"
        echo ""
        return 0
    fi
    
    echo "$spawn" >> /etc/hosts.deny 2>/dev/null || {
        echo "could not write to /etc/hosts.deny" >&2
        return 1
    }
}

# Function to check setup
check_setup() {
    TCPD_DENYLIST=$(get_denylist_file)
    configure_tcpwrappers
    return 0
}

# Connect action - register a connection
do_connect() {
    SEEN=$((SEEN + 1))
    
    if is_whitelisted; then
        return 0
    fi
    
    if is_blacklisted; then
        return 0
    fi
    
    if [ "$SEEN" -lt 3 ]; then
        return 0
    fi
    
    parse_ssh_logs
    
    if [ "$PROTECT_FTP" -eq 1 ]; then
        parse_ftp_logs
    fi
    
    if [ "$PROTECT_SMTP" -eq 1 ] || [ "$PROTECT_MUA" -eq 1 ]; then
        parse_mail_logs
    fi
}

# Whitelist action
do_whitelist() {
    log_verbose "whitelisting $IP"
    WHITE=$(date +%s)
    
    if [ "$ADD_TO_TCPWRAPPERS" -eq 1 ]; then
        allow_tcpwrappers
    fi
    if [ "$ADD_TO_PF" -eq 1 ]; then
        allow_pf
    fi
    if [ "$ADD_TO_IPFW" -eq 1 ]; then
        allow_ipfw
    fi
}

# Blacklist action
do_blacklist() {
    log_verbose "blacklisting $IP"
    BLACK=$(date +%s)
    
    if [ "$ADD_TO_TCPWRAPPERS" -eq 1 ]; then
        block_tcpwrappers
    fi
    if [ "$ADD_TO_PF" -eq 1 ]; then
        block_pf
    fi
    if [ "$ADD_TO_IPFW" -eq 1 ]; then
        block_ipfw
    fi
}

# Delist action
do_delist() {
    do_unblacklist
    do_unwhitelist
}

# Unblacklist
do_unblacklist() {
    log_verbose "unblacklisting $IP"
    BLACK=0
    
    if [ "$ADD_TO_TCPWRAPPERS" -eq 1 ]; then
        unblock_tcpwrappers
    fi
    if [ "$ADD_TO_PF" -eq 1 ]; then
        unblock_pf
    fi
    if [ "$ADD_TO_IPFW" -eq 1 ]; then
        unblock_ipfw
    fi
}

# Unwhitelist
do_unwhitelist() {
    log_verbose "unwhitelisting $IP"
    WHITE=0
}

# Report action
do_report() {
    if [ ! -r "$ROOT_DIR" ]; then
        echo "you cannot read $ROOT_DIR" >&2
        exit 1
    fi
    
    if [ -n "$IP" ] && [ "$VERBOSE" -eq 0 ]; then
        return
    fi
    
    local unique_ips=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM ip_records;")
    local total_seen=$(sqlite3 "$DB_PATH" "SELECT SUM(seen) FROM ip_records;")
    local white_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM ip_records WHERE white > 0;")
    local black_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM ip_records WHERE black > 0;")
    
    echo "   -------- summary ---------"
    printf "%4d unique IPs have connected %s times\n" "$unique_ips" "${total_seen:-0}"
    printf "%4d IPs are whitelisted\n" "$white_count"
    printf "%4d IPs are blacklisted\n" "$black_count"
    echo ""
}

# Parse SSH logs
parse_ssh_logs() {
    local log_files=("/var/log/auth.log" "/var/log/secure" "/var/log/system.log")
    local log_file=""
    
    for file in "${log_files[@]}"; do
        if [ -f "$file" ]; then
            log_file="$file"
            break
        fi
    done
    
    if [ -z "$log_file" ]; then
        log_verbose "unable to find SSH logs"
        return
    fi
    
    local success=0
    local failed=0
    local naughty=0
    
    # Count successful connections
    success=$(grep -c "$IP.*Accepted" "$log_file" 2>/dev/null || true)
    success=${success:-0}
    
    # Count failed password attempts
    failed=$(grep -c "$IP.*Failed password" "$log_file" 2>/dev/null || true)
    failed=${failed:-0}
    
    # Count naughty attempts (invalid user)
    naughty=$(grep -c "$IP.*Invalid user" "$log_file" 2>/dev/null || true)
    naughty=${naughty:-0}
    
    local total=$((success + failed))
    
    log_verbose "SSH: success=$success, failed=$failed, naughty=$naughty, total=$total"
    
    if [ "$success" -gt 0 ]; then
        do_whitelist
        return
    fi
    
    if [ "$naughty" -gt 0 ]; then
        do_blacklist
        return
    fi
    
    if [ "$total" -gt 10 ]; then
        do_blacklist
    fi
}

# Parse FTP logs
parse_ftp_logs() {
    local log_files=("/var/log/xferlog" "/var/log/ftp.log" "/var/log/auth.log")
    local log_file=""
    
    for file in "${log_files[@]}"; do
        if [ -f "$file" ]; then
            log_file="$file"
            break
        fi
    done
    
    if [ -z "$log_file" ]; then
        log_verbose "unable to find FTP logs"
        return
    fi
    
    # Simple FTP log parsing - this can be enhanced
    log_verbose "parsing FTP logs from $log_file"
}

# Parse mail logs
parse_mail_logs() {
    local log_files=("/var/log/mail.log" "/var/log/maillog")
    local log_file=""
    
    for file in "${log_files[@]}"; do
        if [ -f "$file" ]; then
            log_file="$file"
            break
        fi
    done
    
    if [ -z "$log_file" ]; then
        log_verbose "unable to find mail logs"
        return
    fi
    
    # Simple mail log parsing - this can be enhanced
    log_verbose "parsing mail logs from $log_file"
}

# Tcpwrappers: allow IP
allow_tcpwrappers() {
    if [ ! -e "$TCPD_DENYLIST" ]; then
        return
    fi
    
    if [ ! -w "$TCPD_DENYLIST" ]; then
        echo "file $TCPD_DENYLIST is not writable!" >&2
        return
    fi
    
    # Remove the IP from the denylist
    grep -v " $IP " "$TCPD_DENYLIST" > "$TCPD_DENYLIST.tmp" 2>/dev/null || true
    mv "$TCPD_DENYLIST.tmp" "$TCPD_DENYLIST" 2>/dev/null || {
        echo "failed to delist from tcpwrappers" >&2
        return
    }
}

# Tcpwrappers: block IP
block_tcpwrappers() {
    if [ -e "$TCPD_DENYLIST" ] && [ ! -w "$TCPD_DENYLIST" ]; then
        echo "file $TCPD_DENYLIST is not writable!" >&2
        return
    fi
    
    # Prepend the naughty IP to the hosts.deny file
    {
        echo "ALL: $IP : deny"
        if [ -f "$TCPD_DENYLIST" ]; then
            cat "$TCPD_DENYLIST"
        fi
    } > "$TCPD_DENYLIST.tmp" || {
        echo "could not add $IP to blocklist" >&2
        return
    }
    
    mv "$TCPD_DENYLIST.tmp" "$TCPD_DENYLIST" || {
        echo "could not add $IP to blocklist" >&2
        return
    }
}

# Tcpwrappers: unblock IP
unblock_tcpwrappers() {
    allow_tcpwrappers
}

# PF: allow IP
allow_pf() {
    local pfctl=$(which pfctl 2>/dev/null)
    
    if [ -z "$pfctl" ] || [ ! -x "$pfctl" ]; then
        echo "could not find pfctl!" >&2
        return
    fi
    
    # Remove the IP from the PF table
    $pfctl -q -t "$FIREWALL_TABLE" -Tdelete "$IP" 2>/dev/null || {
        echo "failed to remove $IP from PF table $FIREWALL_TABLE" >&2
    }
}

# PF: block IP
block_pf() {
    local pfctl=$(which pfctl 2>/dev/null)
    
    if [ -z "$pfctl" ] || [ ! -x "$pfctl" ]; then
        echo "could not find pfctl!" >&2
        return
    fi
    
    # Add the IP to the PF table
    $pfctl -q -t "$FIREWALL_TABLE" -Tadd "$IP" 2>/dev/null || {
        echo "failed to add $IP to PF table $FIREWALL_TABLE" >&2
    }
}

# PF: unblock IP
unblock_pf() {
    allow_pf
}

# IPFW: allow IP (placeholder)
allow_ipfw() {
    local ipfw=$(which ipfw 2>/dev/null)
    
    if [ -z "$ipfw" ] || [ ! -x "$ipfw" ]; then
        echo "could not find ipfw!" >&2
        return
    fi
    
    # TODO: implement IPFW allow
    log_verbose "IPFW allow not fully implemented"
}

# IPFW: block IP (placeholder)
block_ipfw() {
    local ipfw=$(which ipfw 2>/dev/null)
    
    if [ -z "$ipfw" ] || [ ! -x "$ipfw" ]; then
        echo "could not find ipfw!" >&2
        return
    fi
    
    # TODO: implement IPFW block
    log_verbose "IPFW block not fully implemented"
}

# IPFW: unblock IP
unblock_ipfw() {
    allow_ipfw
}

# Usage/help
show_help() {
    cat << 'EOF'
NAME
    sentry - safe and effective protection against bruteforce attacks

SYNOPSIS
    sentry.sh --ip=N.N.N.N [ --connect | --blacklist | --whitelist | --delist ]
    sentry.sh --report [--verbose --ip=N.N.N.N ]
    sentry.sh --help

DESCRIPTION
    Sentry detects and prevents bruteforce attacks against sshd using minimal
    system resources. Now implemented in bash with SQLite instead of Perl DBM.

OPTIONS
    --ip=IP         Specify an IP address
    --connect       Register a connection by an IP
    --whitelist     Whitelist all future connections
    --blacklist     Deny all future connections
    --delist        Remove an IP from white and blacklists
    --report        Display a report of connections
    --verbose       Show verbose output
    --help          Show this help message

EXAMPLES
    # Register a connection
    sentry.sh --ip=192.168.1.1 --connect
    
    # Whitelist an IP
    sentry.sh --ip=192.168.1.1 --whitelist
    
    # Show report
    sentry.sh --report --verbose

EOF
}

# Main script
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --ip=*)
                IP="${1#*=}"
                shift
                ;;
            --ip)
                IP="$2"
                shift 2
                ;;
            --connect|-c)
                ACTION="connect"
                shift
                ;;
            --whitelist)
                ACTION="whitelist"
                shift
                ;;
            --blacklist)
                ACTION="blacklist"
                shift
                ;;
            --delist)
                ACTION="delist"
                shift
                ;;
            --report)
                ACTION="report"
                shift
                ;;
            --verbose)
                VERBOSE=1
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                show_help
                exit 1
                ;;
        esac
    done
    
    # Initialize database
    init_db
    
    # Check setup
    if [ "$ACTION" != "report" ] && [ "$ACTION" != "help" ]; then
        if ! is_valid_ip; then
            if [ -n "$IP" ]; then
                echo "Invalid IP address: $IP" >&2
            fi
            if [ "$ACTION" != "report" ]; then
                exit 1
            fi
        fi
    fi
    
    # Load IP record if we have an IP
    if [ -n "$IP" ]; then
        load_ip_record
    fi
    
    # Dispatch action
    case "$ACTION" in
        connect)
            check_setup
            do_connect
            ;;
        whitelist)
            do_whitelist
            ;;
        blacklist)
            do_blacklist
            ;;
        delist)
            do_delist
            ;;
        report)
            do_report
            ;;
        *)
            if [ -z "$ACTION" ]; then
                show_help
                exit 1
            fi
            ;;
    esac
    
    # Save IP record if we have an IP
    if [ -n "$IP" ]; then
        save_ip_record
    fi
    
    exit 0
}

# Run main
main "$@"
