# Installation

## Download Sentry

```sh
bash || sh
export SENTRY_URL=https://raw.githubusercontent.com/msimerson/sentry/master/sentry.sh
curl -O $SENTRY_URL || wget $SENTRY_URL || fetch --no-verify-peer $SENTRY_URL
chmod 755 sentry.sh
```

## Install

```sh
mkdir -p /var/db/sentry
mv sentry.sh /var/db/sentry/
```

## Configure tcpwrappers

Add these lines near the top of your `/etc/hosts.allow` file:

```
sshd : /var/db/sentry/hosts.deny : deny
sshd : ALL : spawn /var/db/sentry/sentry.sh --connect --ip=%a : allow
```

## Test

```sh
/var/db/sentry/sentry.sh --report
```

That's all!

## Upgrading

```sh
cd /var/db/sentry
curl -O https://raw.githubusercontent.com/msimerson/sentry/master/sentry.sh
chmod 755 sentry.sh
```

## Requirements

- Bash (4.0 or later)
- SQLite3
