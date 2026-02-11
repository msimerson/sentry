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
    ip TEXT PRIMARY KEY,        -- IP address (IPv4 or IPv6) as text
    seen INTEGER DEFAULT 0,     -- Connection count
    allow INTEGER DEFAULT 0,    -- Allow timestamp (0 = not allowed)
    block INTEGER DEFAULT 0     -- Block timestamp (0 = not blocked)
);
```

**Benefits of text-based storage:**
- Human-readable: Easy to query with `SELECT * FROM ip_records WHERE ip = '192.168.1.1'`
- Works identically for IPv4 and IPv6
- Supports LIKE queries for subnet searches: `WHERE ip LIKE '192.168.1.%'`
- No hash collisions or integer conversions needed

**Note**: Column names changed from `white`/`black` to `allow`/`block` in v2.00+.

### File Locations

Both versions use the same directory structure:
- Default root: `/var/db/sentry/`
- Database: `sentry.db` (new) vs `sentry.dbm` (old)
- Deny list: `hosts.deny`
- Script: `sentry` (new) vs `sentry.pl` (old)

### Command Line Interface

The command-line interface is identical:

```bash
# Perl version
sentry.pl --ip=192.168.1.1 --connect

# Bash version
sentry --ip=192.168.1.1 --connect
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

## Installation

### Requirements

- Bash (version 4.0 or later recommended)
- SQLite3 (`sqlite3` command-line tool)

### Installing the Bash Version

1. Download the script:
```bash
curl -o /var/db/sentry/sentry https://raw.githubusercontent.com/msimerson/sentry/master/sentry.sh
chmod 755 /var/db/sentry/sentry
```

2. Update your `/etc/hosts.allow` to use the new script:
```
# Old:
sshd : ALL : spawn /var/db/sentry/sentry.pl --connect --ip=%a : allow

# New:
sshd : ALL : spawn /var/db/sentry/sentry --connect --ip=%a : allow
```

3. Test it:
```bash
/var/db/sentry/sentry --report
```

## Configuration

Configuration is done by editing variables at the top of `sentry`:

```bash
ROOT_DIR="${ROOT_DIR:-/var/db/sentry}"
ADD_TO_TCPWRAPPERS="${ADD_TO_TCPWRAPPERS:-1}"
ADD_TO_PF="${ADD_TO_PF:-0}"
ADD_TO_IPFW="${ADD_TO_IPFW:-0}"
EXPIRE_BLOCK_DAYS="${EXPIRE_BLOCK_DAYS:-90}"
PROTECT_FTP="${PROTECT_FTP:-1}"
PROTECT_SMTP="${PROTECT_SMTP:-0}"
PROTECT_MUA="${PROTECT_MUA:-1}"
```

Alternatively, you can override these via environment variables:

```bash
ROOT_DIR=/tmp/sentry_test sentry --report
```

## Troubleshooting

### SQLite Database Locked

If you see "database is locked" errors, ensure no other processes are accessing the database simultaneously.

### Log Files Not Found

The script looks for logs in standard locations:
- SSH: `/var/log/auth.log`, `/var/log/secure`, `/var/log/system.log`
- FTP: `/var/log/xferlog`, `/var/log/ftp.log`
- Mail: `/var/log/mail.log`, `/var/log/maillog`

Adjust the script if your logs are in different locations.

## Differences and Limitations

### What's Different

1. **Simplified Log Parsing**: The log parsing in the bash version is simpler than the Perl version. It may not catch all edge cases.

2. **No Auto-Update**: The `--update` option from the Perl version is not implemented in the bash version. Update manually via git or curl.

3. **IPFW Support**: The IPFW firewall support is not implemented.

## Support

For issues or questions:
- GitHub: https://github.com/msimerson/sentry
- Original documentation: [README.md](README.md)
