# Sentry Bash Port - Migration Guide

## Overview

Sentry has been ported from Perl to Bash, with the database backend changed from DBM to SQLite. This provides several benefits:

- **Simpler dependencies**: Only requires bash and sqlite3 (both commonly available)
- **Better database management**: SQLite provides better reliability and easier querying
- **Easier to understand**: Bash is more familiar to many system administrators
- **Backwards compatible**: Can run alongside the Perl version

## What Changed

### Database Format

The old Perl version used DBM files (`sentry.dbm`). The new Bash version uses SQLite (`sentry.db`).

**Old format (DBM):**
- Key: IP address as integer
- Value: `seen^white^black` (caret-delimited)

**New format (SQLite):**
```sql
CREATE TABLE ip_records (
    key INTEGER PRIMARY KEY,    -- IP as integer (or hash for IPv6)
    ip TEXT NOT NULL,           -- IP as dotted notation or IPv6
    seen INTEGER DEFAULT 0,     -- Connection count
    allow INTEGER DEFAULT 0,    -- Allow timestamp (0 = not allowed)
    block INTEGER DEFAULT 0     -- Block timestamp (0 = not blocked)
);
```

**Note**: Column names changed from `white`/`black` to `allow`/`block` in v2.00+.

### File Locations

Both versions use the same directory structure:
- Default root: `/var/db/sentry/`
- Database: `sentry.db` (new) vs `sentry.dbm` (old)
- Deny list: `hosts.deny`
- Script: `sentry.sh` (new) vs `sentry.pl` (old)

### Command Line Interface

The command-line interface is identical:

```bash
# Perl version
sentry.pl --ip=192.168.1.1 --connect

# Bash version
sentry.sh --ip=192.168.1.1 --connect
```

All options work the same way:
- `--ip=IP` - Specify an IP address (IPv4 or IPv6)
- `--connect` - Register a connection
- `--allow` - Allow an IP (replaces `--whitelist`)
- `--block` - Block an IP (replaces `--blacklist`)
- `--delist` - Remove from allow/block lists
- `--report` - Show statistics
- `--verbose` - Verbose output
- `--help` - Show help

**Note**: `--whitelist` and `--blacklist` are maintained for backward compatibility but are deprecated in favor of `--allow` and `--block`.
- `--help` - Show help

## Installation

### Requirements

- Bash (version 4.0 or later recommended)
- SQLite3 (`sqlite3` command-line tool)

### Installing the Bash Version

1. Download the script:
```bash
cd /var/db/sentry
curl -O https://raw.githubusercontent.com/msimerson/sentry/master/sentry.sh
chmod 755 sentry.sh
```

2. Update your `/etc/hosts.allow` to use the new script:
```
# Old:
sshd : ALL : spawn /var/db/sentry/sentry.pl --connect --ip=%a : allow

# New:
sshd : ALL : spawn /var/db/sentry/sentry.sh --connect --ip=%a : allow
```

3. Test it:
```bash
/var/db/sentry/sentry.sh --report
```

## Migration from Perl to Bash

If you're currently using the Perl version and want to migrate:

### Option 1: Fresh Start (Recommended for Testing)

Simply install the bash version in parallel and point tcpwrappers to use it. The database will start fresh.

### Option 2: Data Migration (Advanced)

You can migrate your existing data from DBM to SQLite:

```bash
#!/bin/bash
# Migration script (example - customize as needed)

OLD_DB="/var/db/sentry/sentry.dbm"
NEW_DB="/var/db/sentry/sentry.db"

# Create new database
sqlite3 "$NEW_DB" "CREATE TABLE IF NOT EXISTS ip_records (
    key INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    seen INTEGER DEFAULT 0,
    white INTEGER DEFAULT 0,
    black INTEGER DEFAULT 0
);"

# Note: Direct DBM to SQLite migration requires Perl
# You can export the DBM data first, then import to SQLite
perl -MDBM::Deep -e 'use DBM::Deep; my $db = DBM::Deep->new("'"$OLD_DB"'"); ...'
```

### Option 3: Run Both Versions

You can keep both versions installed and switch between them as needed:

```bash
# Use Perl version
/var/db/sentry/sentry.pl --report

# Use Bash version
/var/db/sentry/sentry.sh --report
```

Note: They maintain separate databases, so statistics won't be shared.

## Configuration

Configuration is done by editing variables at the top of `sentry.sh`:

```bash
ROOT_DIR="${ROOT_DIR:-/var/db/sentry}"
ADD_TO_TCPWRAPPERS="${ADD_TO_TCPWRAPPERS:-1}"
ADD_TO_PF="${ADD_TO_PF:-1}"
ADD_TO_IPFW="${ADD_TO_IPFW:-0}"
EXPIRE_BLOCK_DAYS="${EXPIRE_BLOCK_DAYS:-90}"
PROTECT_FTP="${PROTECT_FTP:-1}"
PROTECT_SMTP="${PROTECT_SMTP:-0}"
PROTECT_MUA="${PROTECT_MUA:-1}"
```

Alternatively, you can override these via environment variables:

```bash
ROOT_DIR=/tmp/sentry_test sentry.sh --report
```

## Testing

Test the bash version before deploying to production:

```bash
# Create a test directory
mkdir -p /tmp/sentry_test

# Test basic functionality
ROOT_DIR=/tmp/sentry_test /var/db/sentry/sentry.sh --ip=192.168.1.1 --connect
ROOT_DIR=/tmp/sentry_test /var/db/sentry/sentry.sh --report

# Test allow
ROOT_DIR=/tmp/sentry_test /var/db/sentry/sentry.sh --ip=192.168.1.1 --allow

# Test block
ROOT_DIR=/tmp/sentry_test /var/db/sentry/sentry.sh --ip=10.0.0.1 --block

# Check the database
sqlite3 /tmp/sentry_test/sentry.db "SELECT * FROM ip_records;"
```

## Troubleshooting

### SQLite Database Locked

If you see "database is locked" errors, ensure no other processes are accessing the database simultaneously.

### Permissions

Ensure the script has proper permissions:
```bash
chmod 755 /var/db/sentry/sentry.sh
chown root:root /var/db/sentry/sentry.sh
```

### Log Files Not Found

The script looks for logs in standard locations:
- SSH: `/var/log/auth.log`, `/var/log/secure`, `/var/log/system.log`
- FTP: `/var/log/xferlog`, `/var/log/ftp.log`
- Mail: `/var/log/mail.log`, `/var/log/maillog`

Adjust the script if your logs are in different locations.

## Differences and Limitations

### What's the Same

- All core functionality (connect, allow, block, delist, report)
- Tcpwrappers integration
- PF firewall integration
- IP validation
- Automatic allow-listing after successful logins
- Blocking after naughty attempts

### What's Different

1. **IPv6 Support**: The bash version now supports both IPv4 and IPv6 addresses.

2. **Simplified Log Parsing**: The log parsing in the bash version is simpler than the Perl version. It may not catch all edge cases.

3. **No Auto-Update**: The `--update` option from the Perl version is not implemented in the bash version. Update manually via git or curl.

4. **IPFW Support**: The IPFW firewall support is a placeholder and not fully implemented.

## Support

For issues or questions:
- GitHub: https://github.com/msimerson/sentry
- Original documentation: [README.md](README.md)
