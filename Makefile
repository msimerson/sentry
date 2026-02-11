.PHONY: test install clean

all: test

test:
	@./test/run-tests.sh

install:
	@echo "Installing sentry.sh to /var/db/sentry/"
	@mkdir -p /var/db/sentry
	@cp sentry.sh /var/db/sentry/sentry
	@chmod 755 /var/db/sentry/sentry
	@echo "Installation complete"
	@echo ""
	@echo "Add these lines to /etc/hosts.allow:"
	@echo "sshd : /var/db/sentry/hosts.deny : deny"
	@echo "sshd : ALL : spawn /var/db/sentry/sentry --connect --ip=%a : allow"

clean:
	@rm -f /tmp/test_output_*
	@rm -f /tmp/shellcheck_out.*
	@echo "Cleanup complete"
