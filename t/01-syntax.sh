#!/bin/bash
# Test: Syntax check for bash scripts

set -e

echo "Checking bash syntax..."

ERRORS=0

# Check sentry.sh
if [ -f "sentry.sh" ]; then
    echo -n "  sentry.sh... "
    if bash -n sentry.sh 2>/dev/null; then
        echo "OK"
    else
        echo "FAIL"
        bash -n sentry.sh
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "  sentry.sh not found, skipping"
fi

# Check check_sentry
if [ -f "check_sentry" ]; then
    echo -n "  check_sentry... "
    # Determine the shell from shebang
    SHEBANG=$(head -n1 check_sentry)
    if [[ "$SHEBANG" =~ bash ]]; then
        SHELL_CMD="bash"
    else
        SHELL_CMD="sh"
    fi
    
    if $SHELL_CMD -n check_sentry 2>/dev/null; then
        echo "OK"
    else
        echo "FAIL"
        $SHELL_CMD -n check_sentry
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "  check_sentry not found, skipping"
fi

if [ $ERRORS -gt 0 ]; then
    echo "Syntax check failed with $ERRORS error(s)"
    exit 1
fi

echo "All syntax checks passed"
exit 0
