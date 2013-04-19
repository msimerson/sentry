
use Config qw/ myconfig /;
use Data::Dumper;
use English qw/ -no_match_vars /;
use Test::More tests => 2;

use lib 'lib';

my $this_perl = $Config{'perlpath'} || $EXECUTABLE_NAME;

ok( $this_perl, "this_perl: $this_perl" );

if ($OSNAME ne 'VMS' && $Config{_exe} ) {
    $this_perl .= $Config{_exe}
        unless $this_perl =~ m/$Config{_exe}$/i;
}

my $cmd = "$this_perl -c 'sentry.pl'";
my $r = system "$cmd 2>/dev/null >/dev/null";
ok( $r == 0, "syntax sentry.pl");

