# NAME

sentry - safe and effective protection against bruteforce attacks

# VERSIONS

Sentry is available in two implementations:
- **Bash version** (`sentry.sh`): Uses SQLite database, minimal dependencies
- **Perl version** (`sentry.pl`): Original implementation using DBM

See [MIGRATION.md](MIGRATION.md) for details on the differences and how to migrate.

# SYNOPSIS

```sh
sentry --ip=N.N.N.N [ --connect | --blacklist | --whitelist | --delist ]
sentry --report [--verbose --ip=N.N.N.N ]
sentry --help
sentry --update  # Perl version only
```

# ADDITIONAL DOCUMENTATION

* [Install](INSTALL.md)
* [FAQ](FAQ.md)
* [Migration Guide](MIGRATION.md) - For migrating from Perl to Bash version

# DESCRIPTION

Sentry detects and prevents bruteforce attacks against sshd using minimal system resources.

## SAFE

To prevent inadvertant lockouts, Sentry auto-whitelists IPs that have connected more than 3 times and succeeded at least once. Now that forgetful colleague behind the office NAT router won't get us locked out of our system. Again. Nor the admin whose script just failed to login 12 times in 2 seconds.

Sentry includes support for adding IPs to a firewall. Support for IPFW, PF, ipchains is included. Firewall support is disabled by default. Firewall rules may terminate existing session(s) to the host (attn. IPFW users). Get your IPs whitelisted (connect 3x or use --whitelist) before enabling the firewall option.

## SIMPLE

Sentry is available in both Perl and Bash implementations:

- **Perl version**: No dependencies beyond core Perl modules
- **Bash version**: Requires only bash and sqlite3 (commonly available)

Installation and deployment is extremely simple for both versions.

## FLEXIBLE

Sentry supports blocking connection attempts using tcpwrappers and several
popular firewalls. It is easy to extend sentry to support additional
blocking lists.

Sentry was written to protect the SSH daemon but also blocks on FTP and MUA logs. As this was written, the primary attack platform in use is bot nets comprised of exploited PCs on high-speed internet connections. These bots are used for carrying out SSH attacks as well as spam delivery. Blocking bots prevents multiple attack vectors.

The programming style of sentry makes it easy to insert code for additonal functionality.

## EFFICIENT

The primary goal of Sentry is to minimize the resources an attacker can steal, while consuming minimal resources itself. Most bruteforce blocking apps (denyhosts, fail2ban, sshdfilter) expect to run as a daemon, tailing a log file. That requires a language interpreter to always be running, consuming at least 10MB of RAM. A single hardware node with dozens of virtual servers will lose hundreds of megs to daemon protection. Sentry uses resources only when connections are made.

Once an IP is blacklisted for abuse, whether by tcpd or a firewall, the resources it can consume are practically zero.

# REQUIRED ARGUMENTS

- ip

    An IP address. The IP should come from a reliable source that is
    difficult to spoof. Tcpwrappers is an excellent source. UDP connections
    are a poor source as they are easily spoofed. The log files of TCP daemons
    can be good source if they are parsed carefully to avoid log injection attacks.

All actions except __report__ and __help__ require an IP address. The IP address can
be manually specified by an administrator, or preferably passed in by a TCP
server such as tcpd (tcpwrappers), inetd, or tcpserver (daemontools).

# ACTIONS

- blacklist

    deny all future connections

- whitelist

    whitelist all future connections, remove the IP from the blacklists,
    and make it immune to future connection tests.

- delist

    remove an IP from the white and blacklists. This is useful for testing
    that sentry is working as expected.

- connect

    register a connection by an IP. The connect method will log the attempt
    and the time. See CONNECT.

- update

    Check the most recent version of sentry against the installed version and update if a newer version is available. This is most reliable when LWP::UserAgent is installed.

# EXAMPLES

See
[https://github.com/msimerson/sentry/wiki/Examples](https://github.com/msimerson/sentry/wiki/Examples)


# NAUGHTY

Sentry has flexible rules for what constitutes a naughty connection. For SSH,
attempts to log in as an invalid user are considered naughty.
See the configuration section in the script related settings.


# CONNECT

When new connections arrive, the connect method will log the attempt
and the time. If the IP is white or blacklisted, sentry exits immediately.

Next, sentry checks to see if the IP has been seen more than 3 times. If so,
check the logs for successful, failed, and naughty attempts from that IP.
If there are any successful logins, whitelist the IP and exit.

If there are no successful logins and there are naughty ones, blacklist
the IP. If there are no successful and no naughty attempts but more than 10
connection attempts, blacklist the IP. See also NAUGHTY.


# CONFIGURATION AND ENVIRONMENT

There is a very brief configuration section at the top of the script. Once
your IP is whitelisted, update the booleans for your firewall preference
and Sentry will update your firewall too.

Sentry does NOT make changes to your firewall configuration. It merely adds
IPs to a table/list/chain. It does this dynamically and it is up to the
firewall administrator to add a rule that does whatever you'd like with the
IPs in the sentry table.

See also: [PF](https://github.com/msimerson/sentry/wiki/PF)


# DIAGNOSTICS

Sentry can be run with --verbose which will print informational messages
as it runs.

# DEPENDENCIES

Sentry uses only modules built into perl. Additional modules may be used in
the future but Sentry will not depend upon them. In other words, if you extend
Sentry with modules are aren't built-ins, also include a fallback method.

# BUGS AND LIMITATIONS


The IPFW and ipchains code is barely tested.

Report problems to author.


# AUTHOR

Matt Simerson (@msimerson)


# ACKNOWLEDGEMENTS

Those who came before me: denyhosts, fail2ban, sshblacklist, et al


# LICENCE AND COPYRIGHT

Copyright (c) 2015 The Network People, Inc. http://www.tnpi.net/

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See [perlartistic](http://search.cpan.org/perldoc?perlartistic).

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
