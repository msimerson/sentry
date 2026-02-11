#!/bin/bash
# Test runner for sentry
# Uses bash, shellcheck for validation

set -e

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$TESTS_DIR/.."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
SKIPPED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_file="$2"
    
    if [ ! -f "$test_file" ] || [ ! -x "$test_file" ]; then
        echo -e "${YELLOW}SKIP${NC} $test_name (not found or not executable)"
        SKIPPED=$((SKIPPED + 1))
        return
    fi
    
    echo -n "Running $test_name... "
    
    if "$test_file" > /tmp/test_output_$$ 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAIL${NC}"
        cat /tmp/test_output_$$
        FAILED=$((FAILED + 1))
    fi
    
    rm -f /tmp/test_output_$$
}

# Run all tests
echo "Running sentry tests..."
echo ""

# Find and run all test scripts
for test_script in "$TESTS_DIR"/*.sh; do
    if [ -f "$test_script" ] && [ -x "$test_script" ]; then
        # Skip the test runner itself
        if [ "$(basename "$test_script")" = "run-tests.sh" ]; then
            continue
        fi
        test_name=$(basename "$test_script" .sh)
        run_test "$test_name" "$test_script"
    fi
done

# Summary
echo ""
echo "===================="
echo "Test Summary:"
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo "===================="

if [ $FAILED -gt 0 ]; then
    exit 1
fi

exit 0
