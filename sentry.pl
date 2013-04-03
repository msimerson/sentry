#!/usr/bin/perl
use strict;
use warnings;

our $VERSION = '0.22';

# configuration. Adjust these to taste (boolean, unless noted)
my $root_dir              = '/var/db/sentry';
my $add_to_tcpwrappers    = 1;
my $add_to_pf             = 0;
my $add_to_ipfw           = 0;    # untested
my $add_to_iptables       = 0;    # untested
my $firewall_table        = 'sentry_blacklist';
my $expire_from_blacklist = 90;   # in days, 0 to disable
my $protect_ftp           = 1;
my $protect_smtp          = 0;

# perl built-in modules
use Data::Dumper;
use English qw( -no_match_vars );
use File::Copy;
use File::Path;
use Getopt::Long;
use Pod::Usage;

# parse command line options
Getopt::Long::GetOptions(
    'ip=s'      => \my $ip,
    'connect'   => \my $connect,
    'delist'    => \my $delist,
    'whitelist' => \my $whitelist,
    'blacklist' => \my $blacklist,
    'report'    => \my $report,
    'update'    => \my $self_update,
    'verbose'   => \my $verbose,
    'help'      => \my $help,
) or die "error parsing command line options\n";

my $tcpd_denylist = _get_denylist_file();  # where to put hosts.deny entries
my $latest_script = undef;
check_setup() or pod2usage( -verbose => 1);

# dispatch the request
if    ( $report    ) { do_report()    }
elsif ( $connect   ) { do_connect()   }
elsif ( $whitelist ) { do_whitelist() }
elsif ( $blacklist ) { do_blacklist() }
elsif ( $delist    ) { do_delist()    }
elsif ( $help      ) { pod2usage( -verbose => 2) }
else                 { pod2usage( -verbose => 1) };

sub is_valid_ip {

    return unless $ip;
    if ( $ip =~ /^::ffff:/ ) {
# we may see $ip in goofy IPv6 notation: ::ffff:208.75.177.98
        my @bits = split(':', $ip);
        $ip = pop @bits;  # grab everything after the last :
    };
    return if grep( /\./, split( //, $ip ) ) != 3;    # need 3 dots

    my @octets = split( /\./, $ip );
    return unless @octets == 4;                       # need 4 octets

    return if $octets[0] < 1;
    return if grep( $_ eq '255', @octets ) == 4;      # 255.255.255.255 invalid

    foreach (@octets) {
        return unless /^\d{1,3}$/ and $_ >= 0 and $_ <= 255;
        $_ = 0 + $_;
    }

    print "ip $ip is valid\n" if $verbose;
    return $ip
};

sub is_whitelisted {
    return if ! -f _get_path('white');

    print "is whitelisted\n" if $verbose;
    do_unblacklist() if &is_blacklisted;
    return 1;
};

sub is_blacklisted {
    return if ! -f _get_path('black');

    print "is blacklisted\n" if $verbose;

    if ( $expire_from_blacklist ) {
        my ($last_modified) = (stat( _get_path('black' )))[9]; # mtime
        my $days_old = ( time() - $last_modified ) / 3600 / 24;
        do_unblacklist() if $days_old > $expire_from_blacklist;
    };
    return 1;
};

sub check_setup {

    return 1 if $help;

    # check $root_dir is present
    if ( ! -d $root_dir ) {
        print "creating ssh sentry root at $root_dir\n";
        mkpath($root_dir, undef, 0750) 
            or die "unable to create $root_dir: $!\n";
    };

    do_version_check() if ( -r $root_dir && -w $root_dir );
    configure_tcpwrappers();

    return 1 if $report;

    return if ! is_valid_ip();

    print "setup checks succeeded\n" if $verbose;
    return 1;
};

sub configure_tcpwrappers {

    my $is_setup;
    foreach ( '/etc/hosts.allow', '/etc/hosts.deny', $tcpd_denylist ) {
        next if ! $_;
        next if ! -f $_ || ! -r $_;

        open FH, $_;
        my @matches = grep { $_ =~ /sentry/ } <FH>;
        close FH;
        if ( scalar @matches > 0 ) {
            $is_setup++;
            last;
        };
    };

    return 1 if $is_setup;

    my $script_loc = _get_script_location();
    my $spawn = 'sshd : ALL : spawn ' . $script_loc . ' -c --ip=%a : allow';

    if ( $OSNAME =~ /freebsd|linux/ ) {
# FreeBSD & Linux have a modified tcpd, adding support for include files
        print "
NOTICE: you need to add these lines near the top of your /etc/hosts.allow file\n
sshd : $tcpd_denylist : deny
$spawn\n\n";
        return;
    }

    my $write_mode = '>>';
    $write_mode = '>' if ! -e '/etc/hosts.deny';
    open FH, $write_mode, '/etc/hosts.deny' 
        or warn "could not write to /etc/hosts.deny: $!" and return;
    print FH "$spawn\n";
    close FH;
};

sub install_myself {
    my $script_loc = _get_script_location();
    print "installing $0 to $script_loc\n" if $verbose;
    copy( $0, $script_loc ) or warn "unable to copy $0 to $script_loc: $!\n";
    chmod 0755, $script_loc;
    print "installed update to $script_loc\n";
    return 1;
};

sub install_from_web {
    return if ! $latest_script;
    my $script_loc = _get_script_location();

    print "installing latest sentry.pl to $script_loc\n";
    open my $FH, '>', $script_loc or die "oops: $!\n";
    print $FH $latest_script;
    close $FH;
    chmod 0755, $script_loc;
    my ($latest_ver) = $latest_script =~ /VERSION\s*=\s*\'([0-9\.]+)\'/;
    print "upgraded $script_loc to $latest_ver\n";
    return 1;
};

sub do_version_check {

    my $installed_ver = _get_installed_version();
    install_myself() and return if ! $installed_ver;

    return if ! $self_update;

    my $release_ver   = _get_latest_release_version();
    my $this_ver      = $VERSION;

    if ( $installed_ver && $release_ver > $installed_ver ) {
        warn "you have sentry $installed_ver installed, version $release_ver is available\n";
    };
    if ( $installed_ver && $this_ver > $installed_ver ) {
        warn "you have sentry $installed_ver installed, version $release_ver is running\n";
    };

    if ($installed_ver >= $release_ver && $installed_ver >= $this_ver) {
        warn "you are running the latest version of sentry ($installed_ver)\n" if $verbose;
        return;
    };

    install_myself() and return if $this_ver > $release_ver;
    install_from_web() if $release_ver > $this_ver;

    return;
};


sub do_connect {

    my $ip_path = _get_path('seen');
    _make_path($ip_path) if ! -f $ip_path;
    _log_connection($ip_path);

    exit if is_whitelisted();
    exit if is_blacklisted();

    my $seen_count = _count_lines($ip_path);
    exit if $seen_count < 3;

    _parse_ssh_logs();
    _parse_ftp_logs()   if $protect_ftp;
    _parse_mail_logs()  if $protect_smtp;
    exit;
};

sub do_whitelist {
    my $ip_path = _get_path('white');
    _make_path($ip_path) if ! -f $ip_path;

    #printf( " called by %s, %s, %s\n", caller );
    print "whitelisting $ip\n" if $verbose;

    link _get_path('seen' ), $ip_path;

    _allow_tcpwrappers() if $add_to_tcpwrappers;
    _allow_pf()          if $add_to_pf;
    _allow_ipfw()        if $add_to_ipfw;

    return 1;
};

sub do_blacklist {

    my $ip_path = _get_path('black');
    _make_path($ip_path) if ! -f $ip_path;

    #printf( " called by %s, %s, %s\n", caller );
    print "blacklisting $ip\n" if $verbose;

    link _get_path('seen'), $ip_path;

    _block_tcpwrappers() if $add_to_tcpwrappers;
    _block_pf()          if $add_to_pf;
    _block_ipfw()        if $add_to_ipfw;
    
    return 1;
};

sub do_delist {

    print "delisting $ip\n" if $verbose;
    do_unblacklist();
    do_unwhitelist();
};

sub do_unblacklist {

    print "unblacklisting $ip\n" if $verbose;
    my $file = _get_path('black');

    if ( -f $file ) {
        unlink $file or warn "unblacklisting failed: $!\n";
        print "removed file $file\n";
    };

    _unblock_tcpwrappers() if $add_to_tcpwrappers;
    _unblock_pf()          if $add_to_pf;
    _unblock_ipfw()        if $add_to_ipfw;

    return;
};

sub do_unwhitelist {

    print "unwhitelisting $ip\n" if $verbose;
    my $file = _get_path('white');
    return 1 if ! -f $file;

    unlink $file or warn "delisting from whitelist failed: $!\n";
    return;
};

sub do_report {

    if ( ! -r $root_dir ) {
        warn "you cannot read $root_dir: $!\n";
        exit;
    };

    if ( $ip ) {
        my $path = _get_path('seen');

        my $count = _count_lines($path);
        printf "%4.0f connections from $ip\n", $count;

        if ( -f _get_path('white' ) ) { print "\tand it is whitelisted\n"; };
        if ( -f _get_path('black' ) ) { print "\tand it is blacklisted\n"; };
    };

    return if $ip && ! $verbose;

    print "   -------- summary ---------\n";
    foreach ( qw/ seen black white / ) {
        my @files = <$root_dir/$_/*/*/*/*>;
        my $count = scalar @files;
        if ( $_ eq 'seen' ) {
            printf "%4.0f unique IPs have connected", $count;
            chomp @files;
            my $total_connects = 0;
            foreach ( @files ) {
                $total_connects += _count_lines($_);
            };
            print " $total_connects times\n";
        }
        else {
            printf "%4.0f IPs are ${_}listed\n", $count;
        };
    };
    print "\n";

    if ( $ip ) {
        _get_ssh_logs();
        _parse_ftp_logs() if $protect_ftp;
    };
};


sub _get_installed_version {
    my $script_loc = "$root_dir/sentry.pl";
    return if ! -e $script_loc;
    my ($ver) = `grep VERSION $script_loc` =~ /VERSION\s*=\s*\'([0-9\.]+)\'/ or return;
    print "installed version is $ver\n" if $verbose;
    return $ver;
};

sub _get_latest_release_version {

    eval "require LWP::UserAgent";
    if ( $EVAL_ERROR ) {
        warn "LWP::UserAgent not installed, could not determine latest version of sentry\n"; 
        return 0;
    };

    my $ua = LWP::UserAgent->new( timeout => 4);
    my $response = $ua->get('http://www.tnpi.net/internet/sentry.pl');
    $latest_script = $response->decoded_content;
    my ($latest_ver) = $latest_script =~ /VERSION\s*=\s*\'([0-9\.]+)\'/;

    return 0 if ! $latest_ver;  # couldn't determine latest version
    return $latest_ver;
};

sub _get_script_location {
    return "$root_dir/sentry.pl";
};

sub _get_path {
    my $dir = shift;

    my @parts = split(/\./, $ip);
    my $path = "$root_dir/$dir/" . join '/', @parts;
    #print "path: $path\n";
    return $path;
};

sub _make_path {
    my $path = shift;

    my @parts = split(/\//, $path);  # split path into array
    pop @parts;                      # discard the filename
    $path = join('/', @parts);       # put it back together

    return 1 if -d $path;            # exit if it exists
    mkpath( $path ) and return 1;    # create it

    warn "unable to create $path\n";
    return;
}

sub _count_lines {
    my $path = shift;

    my $count;
    return 0 if ! -f $path;

    open my $FH, '<', $path;
    while ( <$FH> ) { $count++ };
    close $FH;
    return $count;
};

sub _get_denylist_file {

# Linux and FreeBSD systems have custom versions of libwrap that allow you 
# to store IP lists in file referenced from hosts.allow or hosts.deny. 
# On those systems, dump the blacklisted IPs into a special file

    return "$root_dir/hosts.deny" if $OSNAME =~ /linux|freebsd/i;
    return "/etc/hosts.deny";
};

sub _log_connection {
    my $ip_path = shift;

    open my $SEEN, '>>', $ip_path 
        or warn "unable to open for append: $ip_path: $!" and return;
    print $SEEN time() . "\n";
    close $SEEN;

    return;
};


sub _allow_tcpwrappers {

    return if ! -e $tcpd_denylist;

    if ( ! -w $tcpd_denylist ) {
        warn "file $tcpd_denylist is not writable!\n";
        return;
    };

    my $err = "failed to delist from tcpwrappers\n";
    my $tmp = "$tcpd_denylist.tmp";
    open(TMP, '>', $tmp) or warn $err and return;
    open CUR, '<', $tcpd_denylist or warn $err and return;
    while ( <CUR> ) {
        next if $_ =~ / $ip /;  # discard the IP we want to whitelist
        print TMP $_;
    };
    close TMP;
    close CUR;
    move( "$tcpd_denylist.tmp", $tcpd_denylist) or $err;
};

sub _allow_ipfw {

    my $ipfw = `which ipfw`;
    chomp $ipfw;
    if ( !$ipfw || ! -x $ipfw ) {
        warn "could not find ipfw!";
        return;
    };

    # TODO: look up the rule number and delete it
    my $rule_num = '';
    my $cmd = "delete $rule_num\n";
};

sub _allow_pf {

    my $pfctl = `which pfctl`;
    chomp $pfctl;
    if ( ! -x $pfctl ) {
        warn "could not find pfctl!";
        return;
    };

    # remove the IP from the PF table
    my $cmd = "-q -t $firewall_table -Tdelete $ip";
    system "$pfctl $cmd" 
        and warn "failed to remove $ip from PF table $firewall_table";
};


sub _block_tcpwrappers {

    if ( -e $tcpd_denylist && ! -w $tcpd_denylist ) {
        warn "file $tcpd_denylist is not writable!\n";
        return;
    };

    my $error = "could not add $ip to blocklist: $!\n";

    # prepend the naughty IP to the hosts.deny file
    open (my $TMP, '>', "$tcpd_denylist.tmp") or warn $error and return;
### WARY: THAR BE DRAGONS HERE!
    print $TMP "ALL: $ip : deny\n";
# Linux and FreeBSD support an external filename referenced from
# /etc/hosts.[allow|deny]. However, that filename parsing is not
# identical to /etc/hosts.allow. Specifically, this works as 
# expected in /etc/hosts.allow:
#    ALL : N.N.N.N : deny
# but it does not work in an external file! Be sure to use this syntax:
#    ALL: N.N.N.N : deny
# Lest thee find thyself wishing thou hadst
### /WARY

    # append the current hosts.deny to the temp file
    if ( -e $tcpd_denylist && -r $tcpd_denylist ) {
        open my $BL, '<', $tcpd_denylist or warn $error and return;
        while ( my $line = <$BL> ) {
            print $TMP $line;
        }
        close $BL;
    }
    close $TMP;

    # and finally install the new file
    move( "$tcpd_denylist.tmp", $tcpd_denylist );
};

sub _block_ipfw {

    my $ipfw = `which ipfw`;
    chomp $ipfw;
    if ( !$ipfw || ! -x $ipfw ) {
        warn "could not find ipfw!";
        return;
    };

# TODO: set this to a reasonable default
    my $cmd = "add deny all from $ip to any";
    warn "$ipfw $cmd\n";
    #system "$ipfw $cmd";  # TODO: this this
};

sub _block_pf {

    my $pfctl = `which pfctl`;
    chomp $pfctl;
    if ( ! -x $pfctl ) {
        warn "could not find pfctl!";
        return;
    };

    # add the IP to the chosen PF table
    my $args = "-q -t $firewall_table -T add $ip";
    #warn "$pfctl $args\n";
    system "$pfctl $args" and warn "failed to add $ip to PF table $firewall_table";

    #  kill all state entries for the blocked host
    system "$pfctl -q -k $ip";
};

sub _unblock_tcpwrappers {

    if ( ! -e $tcpd_denylist ) {
        warn "IP $ip not blocked in tcpwrappers\n";
        return;
    };

    if ( ! -w $tcpd_denylist || ! -w "$tcpd_denylist.tmp" ) {
        warn "file $tcpd_denylist or enclosing dir is not writable!\n";
        return;
    };

    my $error = "could not remove $ip from blocklist: $!\n";

    # open a temp file
    open (my $TMP, '>', "$tcpd_denylist.tmp") or warn $error and return;

    # cat the current hosts.deny to the temp file, omitting $ip
    open my $BL, '<', $tcpd_denylist or warn $error and return;
    while ( my $line = <$BL> ) {
        next if $line =~ /$ip/;
        print $TMP $line;
    }
    close $BL;
    close $TMP;

    # install the new file
    move( "$tcpd_denylist.tmp", $tcpd_denylist );
};

sub _unblock_ipfw {

    my $ipfw = `which ipfw`;
    chomp $ipfw;
    if ( !$ipfw || ! -x $ipfw ) {
        warn "could not find ipfw!";
        return;
    };

# TODO: test that this is reasonable
    my $cmd = "delete deny all from $ip to any";
    warn "$ipfw $cmd\n";
    #system "$ipfw $cmd";
};

sub _unblock_pf {

    my $pfctl = `which pfctl`;
    chomp $pfctl;
    if ( ! -x $pfctl ) {
        warn "could not find pfctl!";
        return;
    };

    # add the IP to the chosen PF table
    my $args = "-q -t $firewall_table -T delete $ip";
    #warn "$pfctl $args\n";
    system "$pfctl $args" and warn "failed to delete $ip from PF table $firewall_table";
    return 1;
};


sub _parse_ssh_logs {
    my $ssh_attempts = _get_ssh_logs();

# fail safely. If we can't parse the logs, skip the white/blacklist steps
    return if ! $ssh_attempts;

    if ( $ssh_attempts->{success} ) { do_whitelist(); exit; };
    if ( $ssh_attempts->{naughty} ) { do_blacklist(); exit; };

# do not use $seen_count here. If the ssh log parsing failed for any reason, 
# legit users would not get whitelisted, and then after 10 attempts they
# would get backlisted.

    # no success or naughty, but > 10 connects, blacklist
    do_blacklist() if $ssh_attempts->{total} > 10;
};

sub _get_ssh_logs {

    my $logfile = _get_sshd_log_location();
    return if ! -f $logfile;
    print "checking for SSH logins in $logfile\n" if $verbose;

    my %count;
    open FH, $logfile or warn "unable to read $logfile: $!\n" and return;
    while ( my $line = <FH> ) {
        chomp $line;
        next if $line !~ / sshd/;
        next if $line !~ /$ip/;

# consider using Parse::Syslog if available
#
# WARNING: if you modify this, be mindful of log injection attacks.
# Anchor any regexps or otherwise exclude the user modifiable portions of the 
# log entries when parsing 

        my @bits = split ' ', $line;  # This is more efficient than a regexp
        if    ( $bits[5] eq 'Accepted' ) { $count{success}++  } 
        elsif ( $bits[5] eq 'Invalid'  ) { $count{naughty}++  } 
        elsif ( $bits[5] eq 'Failed'   ) { $count{failed}++   }
        elsif ( $bits[5] eq 'Did'      ) { $count{probed}++   }
        elsif ( $bits[5] eq 'warning:' ) { $count{warnings}++ }
        elsif ( $bits[5] eq '(pam_unix)' ) {
            $count{failed}++ and next if $line =~ /authentication failure; /;
            $count{naughty}++ and next if $line =~ /check pass; user unknown$/;
            print "pam_unix unknown: $line\n";
        }
        elsif ( $bits[5] eq 'error:' ) {
            if ( $bits[6] eq 'PAM:' ) {
# FreeBSD PAM authentication
                $count{failed}++ and next if $line =~ /authentication error/;
                $count{naughty}++ and next if $line =~ /illegal user/;
            };
            $count{errors}++;
        }
        else {
#            if ( $line =~ /POSSIBLE BREAK-IN ATTEMPT!$/ ) {
# This only means their forward/reverse DNS isn't set up properly. Not a
# good criteria for blacklisting
#                $count{naughty}++;
#            };
# 
#            if ( $line =~ /Did not receive identification string from/ ) {
# This entry means that something connected using the SSH protocol, but didn't
# attempt to authenticate. This could a SSH version probe, or a 
# monitoring tool like Nagios or Hobbit.
#            };

            $count{unknown}++;
            print "unknown: $bits[5]: $line\n";
        }
    };
    close FH;

    print Dumper(\%count) if $verbose;
    foreach ( qw/ success naughty errors failed probed warning unknown / ) {
        $count{total} += $count{$_} || 0;
    };

    return \%count;
};

sub _get_sshd_log_location {

# TODO
# a. check the date on the file, and make sure it is within the past month
# b. sample the file, and make sure its contents are what we expect

    # check the most common places
    my @log_files;
    push @log_files, 'auth.log';     # freebsd, debian
    push @log_files, 'secure';       # centos
    push @log_files, 'secure.log';   # darwin

    foreach ( @log_files ) {
        return "/var/log/$_" if -f "/var/log/$_";
    };

    # os specific locations (some are legacy)
    my $log;
    $log = '/var/log/system.log'      if $OSNAME =~ /darwin/i;
    $log = '/var/log/messages'        if $OSNAME =~ /freebsd/i;
    $log = '/var/log/messages'        if $OSNAME =~ /linux/i;
    $log = '/var/log/syslog'          if $OSNAME =~ /solaris/i;
    $log = '/var/adm/SYSLOG'          if $OSNAME =~ /irix/i;
    $log = '/var/adm/messages'        if $OSNAME =~ /aix/i;
    $log = '/var/log/messages'        if $OSNAME =~ /bsd/i;
    $log = '/usr/spool/mqueue/syslog' if $OSNAME =~ /hpux/i;

    return $log if -f $log;
    warn "unable to find your sshd logs.\n";

# TODO: check /etc/syslog.conf for location?
    return;
};


sub _parse_mail_logs {
    my $attempts = _get_mail_logs() or return;

    if ( $attempts->{success} ) { do_whitelist(); exit; };
    if ( $attempts->{naughty} ) { do_blacklist(); exit; };

    do_blacklist() if ($attempts->{total} && $attempts->{total} > 10);
};

sub _get_mail_logs {
# if you want to blacklist spamming IPs, you must alter this to support your
# MTA's log files.
# Note the comments in the _get_ssh_logs sub. 
# I recommend returning a hashref like the one used in the ssh function. 
# If parsing SpamAssassin logs, I'd set success to be anything virus free
#    and a spam score less than 5.
# Naughty would be reserved for more than 3 message with a spam score
# above 10. Or something like that.

    return;
    return {
        success => undef,
        naughty => undef,
        failed  => undef,
        errors  => undef,
    };
};


sub _parse_ftp_logs {
    my $logfile = _get_ftpd_log_location() or return;
    print "checking for FTP logins in $logfile\n" if $verbose;

# sample success
#Nov  8 11:27:51 vhost0 ftpd[29864]: connection from adsl-69-209-115-194.dsl.klmzmi.ameritech.net (69.209.115.194)
#Nov  8 11:27:51 vhost0 ftpd[29864]: FTP LOGIN FROM adsl-69-209-115-194.dsl.klmzmi.ameritech.net as rollings

# sample failed
#Nov 21 21:33:57 vhost0 ftpd[5398]: connection from 87-194-156-116.bethere.co.uk (87.194.156.116)
#Nov 21 21:33:57 vhost0 ftpd[5398]: FTP LOGIN FAILED FROM 87-194-156-116.bethere.co.uk

    open FH, '<', $logfile or warn "unable to read $logfile: $!\n" and return;
    my (%count, $rdns);
    while ( my $line = <FH> ) {
        chomp $line;

        my ($mon, $day, $time, $host, $proc, @mess) = split ' ', $line;
        my $mess = join(' ', @mess);

        next if ! $proc;
        next if $proc !~ /^ftpd/;

        if ( $rdns ) {
            if ( $mess =~ /FROM $rdns/i ) {
                $count{failed}++ if $line =~ /LOGIN FAILED/;
                $count{success}++ if $line =~ /LOGIN FROM/;
                $rdns = undef;
                next;
            };
        };

        ( $rdns ) = $mess =~ /connection from (.*?) \($ip\)/
    };
    close FH;

    foreach ( qw/ success failed / ) {
        $count{total} += $count{$_} || 0;
    };

    print Dumper(\%count) if $verbose;

    if ( $count{success} ) { do_whitelist(); exit; };
    if ( $count{naughty} ) { do_blacklist(); exit; };

    do_blacklist() if $count{total} > 10;
}

sub _get_ftpd_log_location {
    my @log_files;
    push @log_files, 'xferlog';      # freebsd, debian
    push @log_files, 'auth.log';

    foreach ( @log_files ) {
        return "/var/log/$_" if -f "/var/log/$_";
    };

    warn "unable to find FTP logs\n";
    return;
};


__END__

=head1 NAME
 
sentry - safe and effective protection against bruteforce attacks
 

=head1 SYNOPSIS
 
 sentry --ip=N.N.N.N [ --connect | --blacklist | --whitelist | --delist ]
 sentry --report [--verbose --ip=N.N.N.N ]
 sentry --help
 sentry --update


=head1 ADDITIONAL DOCUMENTATION

 * [[ Sentry_Installation | Installation ]]
 * [[ Sentry_FAQ | FAQ ]]


=head1 DESCRIPTION
 
Sentry detects and prevents bruteforce attacks against sshd using minimal system resources.

=head2 SAFE

To prevent inadvertant lockouts, Sentry manages a whitelist of IPs that have connected more than 3 times and succeeded at least once. Never again will that forgetful colleague behind the office NAT router get us locked out of our system. Nor the admin whose script just failed to login 12 times in 2 seconds.

Sentry includes support for adding IPs to a firewall. Support for IPFW, PF, ipchains is included. Firewall support is disabled by default. This is because firewall rules may terminate existing session(s) to the host (attn IPFW users). Get your IPs whitelisted (connect 3x or use --whitelist) before enabling the firewall option.

=head2 SIMPLE

Sentry has an extremely simple database for tracking IPs. This makes it very
easy for administrators to view and manipulate the database using shell commands
and scripts. See the EXAMPLES section.

Sentry is written in perl, which is installed everywhere you find sshd. It has no
dependencies. Installation and deployment is extremely simple.

=head2 FLEXIBLE

Sentry supports blocking connection attempts using tcpwrappers and several 
popular firewalls. It is easy to extend sentry to support additional
blocking lists.

Sentry was written to protect the SSH daemon but anticipates use with other daemons. SMTP support is planned. As this was written, the primary attack platform in use is bot nets comprised of exploited PCs on high-speed internet connections. These bots are used for carrying out SSH attacks as well as spam delivery. Blocking bots prevents multiple attack vectors.

The programming style of sentry makes it easy to insert code for additonal functionality.

=head2 EFFICIENT

The primary goal of Sentry is to minimize the resources an attacker can steal, while consuming minimal resources itself. Most bruteforce blocking apps (denyhosts, fail2ban, sshdfilter) expect to run as a daemon, tailing a log file. That requires a language interpreter to always be running, consuming at least 10MB of RAM. A single hardware node with dozens of virtual servers will lose hundreds of megs to daemon protection.

Sentry uses resources only when connections are made. The worse case scenario is the first connection made by an IP, since it will invoke a perl interpreter. For most connections, Sentry will append a timestamp to a file, stat for the presense of another file and exit. 

Once an IP is blacklisted for abuse, whether by tcpd or a firewall, the resources it can consume are practically zero.

Sentry is not particularly efficient for reporting. The "one file per IP" is superbly minimal for logging and blacklisting, but nearly any database would perform better for reporting. Expect to wait a few seconds for sentry --report.
 
=head1 REQUIRED ARGUMENTS

=over 4

=item ip

An IPv4 address. The IP should come from a reliable source that is 
difficult to spoof. Tcpwrappers is an excellent source. UDP connections 
are a poor source as they are easily spoofed. The log files of TCP daemons
can be good source if they are parsed carefully to avoid log injection attacks.

=back
 
All actions except B<report> and B<help> require an IP address. The IP address can
be manually specified by an administrator, or preferably passed in by a TCP 
server such as tcpd (tcpwrappers), inetd, or tcpserver (daemontools). 

=head1 ACTIONS

=over 

=item blacklist

deny all future connections

=item whitelist

whitelist all future connections, remove the IP from the blacklists, 
and make it immune to future connection tests.

=item delist

remove an IP from the white and blacklists. This is useful for testing
that sentry is working as expected.

=item connect

register a connection by an IP. The connect method will log the attempt
and the time. See CONNECT.

=item update

Check the most recent version of sentry against the installed version and update if a newer version is available.

=back 

=head1 EXAMPLES

=head2 IP REPORT

 $ /var/db/sentry/sentry.pl -r --ip=24.19.45.95
    9 connections from 24.19.45.95
        and it is whitelisted

=head2 HOME GATEWAY REPORT

 $ /var/db/sentry/sentry.pl -r
   -------- summary ---------
   1614 unique IPs have connected 76525 times
   1044 IPs are blacklisted
     18 IPs are whitelisted

=head2 WEB SERVER REPORT

 $ /var/db/sentry/sentry.pl -r
  -------- summary ---------
  1240 unique IPs have connected 285554 times
    40 IPs are blacklisted
     4 IPs are whitelisted

=head2 EUROPEAN DNS MIRROR

 $ /var/db/sentry/sentry.pl -r
 -------- summary ---------
 3484 unique IPs have connected 15391 times
 1127 IPs are blacklisted
    6 IPs are whitelisted

=head2 SHELL COMMANDS

View the total number of connections: 

  cat /var/db/sentry/seen/*/*/*/* | wc -l
       57

the number of unique IPs that have connected:

  ls /var/db/sentry/seen/*/*/*/* | wc -l
        4

the timestamps for every connection 10.0.1.193 made:

  for ts in `cat /var/db/sentry/seen/10/0/1/193`; do date -r $ts; done

    Wed Feb 25 20:18:55 PST 2009
    Wed Feb 25 20:18:57 PST 2009
    ....
    Wed Feb 25 21:18:45 PST 2009

check if 10.0.1.193 is whitelisted

  test -f /var/db/sentry/white/10/0/1/193 && echo yes
  yes

=head1 NAUGHTY

Sentry has flexible rules for what constitutes a naughty connection. For SSH,
attempts to log in as an invalid user are considered naughty. For SMTP, the
sending of a virus, or an email with a high spam score could be considered 
naughty. See the configuration section in the script related settings.


=head1 CONNECT

When new connections arrive, the connect method will log the attempt
and the time. If the IP is white or blacklisted, it will exit immediately.

Next, sentry checks to see if it has seen the IP more than 3 times. If so, 
check the logs for successful, failed, and naughty attempts from that IP.
If there are any successful logins, whitelist the IP and exit. 

If there are no successful logins and there are naughty ones, blacklist 
the IP. If there are no successful and no naughty attempts but more than 10
connection attempts, blacklist the IP. See also NAUGHTY.


=head1 CONFIGURATION AND ENVIRONMENT
 
There is a very brief configuration section at the top of the script. Once
your IP is whitelisted, update the booleans for your firewall preference 
and Sentry will update your firewall too.

Sentry does NOT make changes to your firewall configuration. It merely adds
IPs to a table/list/chain. It does this dynamically and it is up to the 
firewall administrator to add a rule that does whatever you'd like with the
IPs in the sentry table. 

I use the sentry IP table like so with PF:

  table sentry_blacklist persist
  block in quick from <sentry_blacklist>

That blocks all connections from anyone in the sentry table.


=head1 DIAGNOSTICS
 
Sentry can be run with --verbose which will print informational messages
as it runs.

=head1 DEPENDENCIES
 
Sentry uses only modules built into perl. Additional modules may be used in 
the future but Sentry will not depend upon them. In other words, if you extend
Sentry with modules are aren't built-ins, also include a fallback method.

=head1 BUGS AND LIMITATIONS
 
The IPFW and ipchains code is barely tested. 

Report problems to author.
 
=head1 AUTHOR
 
Matt Simerson (msimerson@cpan.org)
 
 
=head1 ACKNOWLEDGEMENTS

Those who came before me: denyhosts, fail2ban, sshblacklist, et al


=head1 LICENCE AND COPYRIGHT
 
Copyright (c) 2012 The Network People, Inc. http://www.tnpi.net/

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


