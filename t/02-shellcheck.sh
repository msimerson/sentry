#!/bin/bash
# Test: ShellCheck validation for shell scripts

set -e

# Check if shellcheck is available
if ! command -v shellcheck &> /dev/null; then
    echo "shellcheck not found, skipping"
    exit 0
fi

echo "Running shellcheck..."

ERRORS=0

# Check sentry.sh
if [ -f "sentry.sh" ]; then
    echo -n "  sentry.sh... "
    if shellcheck -S warning sentry.sh 2>&1 | tee /tmp/shellcheck_out.$$; then
        # Check if there was any output (warnings/errors)
        if [ -s /tmp/shellcheck_out.$$ ]; then
            echo "FAIL"
            ERRORS=$((ERRORS + 1))
        else
            echo "OK"
        fi
    else
        echo "FAIL"
        ERRORS=$((ERRORS + 1))
    fi
    rm -f /tmp/shellcheck_out.$$
else
    echo "  sentry.sh not found, skipping"
fi

# Check check_sentry
if [ -f "check_sentry" ]; then
    echo -n "  check_sentry... "
    if shellcheck -S warning check_sentry 2>&1 | tee /tmp/shellcheck_out.$$; then
        # Check if there was any output (warnings/errors)
        if [ -s /tmp/shellcheck_out.$$ ]; then
            echo "FAIL"
            ERRORS=$((ERRORS + 1))
        else
            echo "OK"
        fi
    else
        echo "FAIL"
        ERRORS=$((ERRORS + 1))
    fi
    rm -f /tmp/shellcheck_out.$$
else
    echo "  check_sentry not found, skipping"
fi

if [ $ERRORS -gt 0 ]; then
    echo "ShellCheck found $ERRORS error(s)"
    exit 1
fi

echo "All shellcheck tests passed"
exit 0
