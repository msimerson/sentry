
use strict;
use warnings;
use Test::More;
use English qw/ -no_match_vars /;

# Check if shellcheck is available
my $shellcheck = `which shellcheck 2>/dev/null`;
chomp $shellcheck;

if ( !$shellcheck || ! -x $shellcheck ) {
    plan skip_all => 'shellcheck not available';
}
else {
    plan tests => 2;
}

# Test sentry.sh
my $sentry_sh = 'sentry.sh';
SKIP: {
    skip "$sentry_sh not found", 1 if ! -f $sentry_sh;
    
    my $cmd = "$shellcheck -S warning $sentry_sh 2>&1";
    my $output = `$cmd`;
    my $exit_code = $? >> 8;
    
    ok( $exit_code == 0, "shellcheck $sentry_sh" ) 
        or diag("ShellCheck output:\n$output");
}

# Test check_sentry
my $check_sentry = 'check_sentry';
SKIP: {
    skip "$check_sentry not found", 1 if ! -f $check_sentry;
    
    my $cmd = "$shellcheck -S warning $check_sentry 2>&1";
    my $output = `$cmd`;
    my $exit_code = $? >> 8;
    
    ok( $exit_code == 0, "shellcheck $check_sentry" )
        or diag("ShellCheck output:\n$output");
}
