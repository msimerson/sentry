#!/usr/bin/env bats
# CLI functional tests for sentry.sh

load ../test/test_helper/bats-support/load
load ../test/test_helper/bats-assert/load

# Setup test environment
setup() {
    # Create a temporary directory for test database
    export TEST_ROOT_DIR=$(mktemp -d)
    export ROOT_DIR="$TEST_ROOT_DIR"
}

# Cleanup test environment
teardown() {
    # Remove test database directory
    if [ -d "$TEST_ROOT_DIR" ]; then
        rm -rf "$TEST_ROOT_DIR"
    fi
}

@test "display help with --help flag" {
    run ./sentry.sh --help
    assert_success
    assert_output --partial "sentry - safe and effective protection against bruteforce attacks"
    assert_output --partial "SYNOPSIS"
    assert_output --partial "OPTIONS"
}

@test "display help with -h flag" {
    run ./sentry.sh -h
    assert_success
    assert_output --partial "SYNOPSIS"
}

@test "display help when no arguments provided" {
    run ./sentry.sh
    assert_failure
}

@test "reject unknown option" {
    run ./sentry.sh --unknown-option
    assert_failure
    assert_output --partial "Unknown option"
}

@test "validate IPv4 address - accept valid 192.168.1.1" {
    run ./sentry.sh --ip=192.168.1.1 --connect
    assert_success
}

@test "validate IPv4 address - accept valid 8.8.8.8" {
    run ./sentry.sh --ip=8.8.8.8 --connect
    assert_success
}

@test "validate IPv4 address - reject 0.0.0.0" {
    run ./sentry.sh --ip=0.0.0.0 --connect
    assert_failure
}

@test "validate IPv4 address - reject 255.255.255.255" {
    run ./sentry.sh --ip=255.255.255.255 --connect
    assert_failure
}

@test "validate IPv4 address - reject invalid 256.1.1.1" {
    run ./sentry.sh --ip=256.1.1.1 --connect
    assert_failure
}

@test "validate IPv4 address - reject invalid 192.168.1" {
    run ./sentry.sh --ip=192.168.1 --connect
    assert_failure
}

@test "validate IPv4 address - reject invalid format" {
    run ./sentry.sh --ip=not.an.ip.address --connect
    assert_failure
}

@test "validate IPv6 address - accept valid 2001:db8::1" {
    run ./sentry.sh --ip=2001:db8::1 --connect
    assert_success
}

@test "validate IPv6 address - accept valid ::1" {
    run ./sentry.sh --ip=::1 --connect
    assert_success
}

@test "validate IPv6 address - accept IPv4-mapped ::ffff:192.168.1.1" {
    run ./sentry.sh --ip=::ffff:192.168.1.1 --connect
    assert_success
}

@test "validate IPv6 address - reject too many colons" {
    run ./sentry.sh --ip=2001:db8::1::2 --connect
    assert_failure
}

@test "validate IPv6 address - reject invalid characters" {
    run ./sentry.sh --ip=2001:db8::gggg:1 --connect
    assert_failure
}

@test "connect action with valid IPv4" {
    run ./sentry.sh --ip=192.168.1.1 --connect
    assert_success
}

@test "connect action with valid IPv6" {
    run ./sentry.sh --ip=2001:db8::1 --connect
    assert_success
}

@test "connect action without IP fails" {
    run ./sentry.sh --connect
    assert_failure
}

@test "block action with valid IP" {
    run ./sentry.sh --ip=10.0.0.1 --block
    assert_success
}

@test "block action without IP fails" {
    run ./sentry.sh --block
    assert_failure
}

@test "allow action with valid IP" {
    run ./sentry.sh --ip=10.0.0.2 --allow
    assert_success
}

@test "allow action without IP fails" {
    run ./sentry.sh --allow
    assert_failure
}

@test "delist action with valid IP" {
    # First block an IP
    ./sentry.sh --ip=10.0.0.3 --block
    
    # Then delist it
    run ./sentry.sh --ip=10.0.0.3 --delist
    assert_success
}

@test "delist action without IP fails" {
    run ./sentry.sh --delist
    assert_failure
}

@test "report action succeeds without IP" {
    run ./sentry.sh --report
    assert_success
}

@test "report action with verbose flag" {
    # Add some connections to report on
    ./sentry.sh --ip=10.0.0.4 --connect
    ./sentry.sh --ip=10.0.0.5 --block
    
    run ./sentry.sh --report --verbose
    assert_success
    assert_output --partial "summary"
}

@test "verbose flag with connect action" {
    run ./sentry.sh --ip=10.0.0.6 --connect --verbose
    assert_success
}

@test "IP argument with equals syntax --ip=VALUE" {
    run ./sentry.sh --ip=192.168.1.100 --connect
    assert_success
}

@test "IP argument with space syntax --ip VALUE" {
    run ./sentry.sh --ip 192.168.1.101 --connect
    assert_success
}

@test "short flag -c for connect" {
    run ./sentry.sh --ip=192.168.1.102 -c
    assert_success
}

@test "multiple flags in different orders" {
    run ./sentry.sh --verbose --ip=192.168.1.103 --connect
    assert_success
}

@test "verbose flag before action" {
    run ./sentry.sh --verbose --ip=192.168.1.104 --block
    assert_success
}

@test "block action creates database entry" {
    run ./sentry.sh --ip=172.16.0.1 --block
    assert_success
    
    # Verify database was created
    assert [ -f "$TEST_ROOT_DIR/sentry.db" ]
}

@test "database persists across commands" {
    ./sentry.sh --ip=10.20.30.40 --connect
    
    # Database should exist after first command
    assert [ -f "$TEST_ROOT_DIR/sentry.db" ]
    
    # Second command should also succeed
    run ./sentry.sh --ip=10.20.30.41 --connect
    assert_success
    
    # Database should still exist
    assert [ -f "$TEST_ROOT_DIR/sentry.db" ]
}

@test "mixed valid and invalid IP addresses" {
    run ./sentry.sh --ip=invalid.ip.address --connect
    assert_failure
}

@test "empty IP address fails" {
    run ./sentry.sh --ip= --connect
    assert_failure
}

@test "whitespace only IP fails" {
    run ./sentry.sh --ip="   " --connect
    assert_failure
}

@test "report shows connection summary" {
    # Add several connections
    ./sentry.sh --ip=10.1.1.1 --connect > /dev/null
    ./sentry.sh --ip=10.1.1.2 --connect > /dev/null
    ./sentry.sh --ip=10.1.1.3 --block > /dev/null
    
    run ./sentry.sh --report --verbose
    assert_success
    assert_output --partial "unique IPs"
    assert_output --partial "blocked"
}

@test "IPv6 with zone ID is handled" {
    # IPv6 addresses may have zone IDs like fe80::1%eth0
    run ./sentry.sh --ip=fe80::1%eth0 --connect
    assert_success
}

@test "connect action idempotent - multiple calls same IP" {
    ./sentry.sh --ip=10.50.50.50 --connect
    run ./sentry.sh --ip=10.50.50.50 --connect
    assert_success
}

@test "allow overwrites block" {
    ./sentry.sh --ip=10.60.60.60 --block
    
    # Allow should overwrite the block
    run ./sentry.sh --ip=10.60.60.60 --allow
    assert_success
}

@test "block overwrites allow" {
    ./sentry.sh --ip=10.70.70.70 --allow
    
    # Block should overwrite the allow
    run ./sentry.sh --ip=10.70.70.70 --block
    assert_success
}

@test "delist clears both allow and block" {
    ./sentry.sh --ip=10.80.80.80 --allow
    ./sentry.sh --ip=10.80.80.81 --block
    
    run ./sentry.sh --ip=10.80.80.80 --delist
    assert_success
    
    run ./sentry.sh --ip=10.80.80.81 --delist
    assert_success
}

@test "report without verbose shows summary" {
    ./sentry.sh --ip=10.90.90.90 --connect
    
    run ./sentry.sh --report
    assert_success
}

@test "handles special IP addresses - localhost" {
    run ./sentry.sh --ip=127.0.0.1 --connect
    assert_success
}

@test "handles special IP addresses - broadcast" {
    # This should fail as broadcast is invalid
    run ./sentry.sh --ip=255.255.255.255 --connect
    assert_failure
}

@test "root directory can be customized" {
    CUSTOM_ROOT=$(mktemp -d)
    export ROOT_DIR="$CUSTOM_ROOT"
    
    run ./sentry.sh --ip=172.20.0.1 --connect
    assert_success
    
    # Database should be in custom root
    assert [ -f "$CUSTOM_ROOT/sentry.db" ]
    
    rm -rf "$CUSTOM_ROOT"
}

@test "concurrent IP operations handled" {
    # Record connections from different IPs
    for i in {1..5}; do
        ./sentry.sh --ip="192.168.100.$i" --connect > /dev/null
    done
    
    run ./sentry.sh --report --verbose
    assert_success
}

@test "all actions require valid IP except report and help" {
    # These should fail without IP
    run ./sentry.sh --connect
    assert_failure
    
    run ./sentry.sh --allow
    assert_failure
    
    run ./sentry.sh --block
    assert_failure
    
    run ./sentry.sh --delist
    assert_failure
}

@test "report and help work without IP" {
    run ./sentry.sh --report
    assert_success
    
    run ./sentry.sh --help
    assert_success
}
