# Sentry Tests

This directory contains the test suite for sentry, using standard shell tools.

## Running Tests

### Run all tests
```bash
make test
# or
./t/run-tests.sh
```

### Run individual tests
```bash
./t/01-syntax.sh      # Bash syntax checks
./t/02-shellcheck.sh  # ShellCheck validation
```

## Test Infrastructure

### Tools Used
- **bash**: Shell syntax checking and test execution
- **shellcheck**: Static analysis for shell scripts
- **make**: Simple build and test orchestration

### Test Files
- `run-tests.sh` - Main test runner that executes all tests
- `01-syntax.sh` - Validates bash syntax for sentry.sh and check_sentry
- `02-shellcheck.sh` - Runs shellcheck on shell scripts

## Adding New Tests

1. Create a new test script: `t/NN-testname.sh`
2. Make it executable: `chmod +x t/NN-testname.sh`
3. Ensure it exits with 0 on success, non-zero on failure
4. The test runner will automatically discover and run it

## Requirements

- bash (4.0 or later)
- shellcheck (optional, test will skip if not available)

## Exit Codes

- 0: All tests passed
- 1: One or more tests failed
- Tests that skip due to missing dependencies exit 0
