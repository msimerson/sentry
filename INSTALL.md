# Installation

## Choose Your Version

Sentry is available in two versions:
- **Bash version** (`sentry.sh`) - Uses SQLite, minimal dependencies
- **Perl version** (`sentry.pl`) - Original version using DBM

Both versions work identically. Choose based on your preference and environment.

## Bash Version Installation

### Requirements
- Bash (4.0 or later)
- SQLite3

### Download Sentry

```sh
bash || sh
export SENTRY_URL=https://raw.githubusercontent.com/msimerson/sentry/master/sentry.sh
curl -O $SENTRY_URL || wget $SENTRY_URL || fetch --no-verify-peer $SENTRY_URL
chmod 755 sentry.sh
```

### Install

```sh
mkdir -p /var/db/sentry
mv sentry.sh /var/db/sentry/
```

### Configure tcpwrappers

Add these lines near the top of your `/etc/hosts.allow` file:

```
sshd : /var/db/sentry/hosts.deny : deny
sshd : ALL : spawn /var/db/sentry/sentry.sh --connect --ip=%a : allow
```

### Test

```sh
/var/db/sentry/sentry.sh --report
```

That's all!

## Perl Version Installation

### Download Sentry

```sh
bash || sh
export SENTRY_URL=https://raw.githubusercontent.com/msimerson/sentry/master/sentry.pl
curl -O $SENTRY_URL || wget $SENTRY_URL || fetch --no-verify-peer $SENTRY_URL
```

### Run it:

```sh
perl sentry.pl --update
```

Running `sentry.pl --update` will:

* create the sentry database (if needed)
* install the perl script (if needed)
* prompt you to edit /etc/hosts.allow (if needed)

That's all.

## Upgrading

### Bash Version

```sh
cd /var/db/sentry
curl -O https://raw.githubusercontent.com/msimerson/sentry/master/sentry.sh
chmod 755 sentry.sh
```

### Perl Version - Easy Way
```sh
perl /var/db/sentry/sentry.pl --update
```

### Perl Version - Hard Way

download as above

```sh
diff sentry.pl /var/db/sentry/sentry.pl
```

resolve any configuration differences

```sh
cp sentry.pl /var/db/sentry/sentry.pl
chmod 755 /var/db/sentry/sentry.pl
```

## Migration

See [MIGRATION.md](MIGRATION.md) for details on migrating between versions.
