
### What Platforms does Sentry Run On?

Sentry should run on any UNIX variant on which tcpwrappers is installed, which
is nearly all of them. Sentry has been tested on:

* FreeBSD
* Mac OS X
* Linux (CentOS, Debian, Ubuntu)

# I get an error saying a perl module isn't available

You are probably running a variant of Linux. The entity that prepared it for
you installed perl without the modules that perl normally ships with. Complain
and ask them to fix it. You can likely fix it yourself by installing perl with
your package manager of choice:

### CentOS

```sh
yum install perl
```

### Debian
```sh
  apt-get install perl
```

