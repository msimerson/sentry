# Installation

## Download Sentry

```sh
bash || sh
export SENTRY_URL=https://raw.githubusercontent.com/msimerson/sentry/master/sentry.pl
curl -O $SENTRY_URL || wget $SENTRY_URL || fetch $SENTRY_URL
```

### Run it:
```sh
perl sentry.pl
```
Running sentry the first time will:

* create the sentry database
* install the perl script
* prompt you to edit /etc/hosts.allow, inserting two lines that enable it.

That's all.

## Upgrading

### Easy Way
```sh
perl /var/db/sentry/sentry.pl --update
```

### Hard Way
download as above

```sh
diff sentry.pl /var/db/sentry/sentry.pl
```

resolve any configuration differences

```sh
cp sentry.pl /var/db/sentry/sentry.pl
chmod 755 /var/db/sentry/sentry.pl
```
