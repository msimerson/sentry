.PHONY: test install clean

# Default target
all: test

# Run tests
test:
	@./t/run-tests.sh

# Install sentry.sh
install:
	@echo "Installing sentry.sh to /var/db/sentry/"
	@mkdir -p /var/db/sentry
	@cp sentry.sh /var/db/sentry/
	@chmod 755 /var/db/sentry/sentry.sh
	@echo "Installation complete"
	@echo ""
	@echo "Add these lines to /etc/hosts.allow:"
	@echo "sshd : /var/db/sentry/hosts.deny : deny"
	@echo "sshd : ALL : spawn /var/db/sentry/sentry.sh --connect --ip=%a : allow"

# Clean up temporary files
clean:
	@rm -f /tmp/test_output_*
	@rm -f /tmp/shellcheck_out.*
	@echo "Cleanup complete"
