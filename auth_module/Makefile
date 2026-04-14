# Makefile for Secure Authentication Module
#
# Build targets:
#   make              — build the PAM shared library
#   make test         — build a standalone test binary
#   make clean        — remove build artifacts
#   make install      — install to /lib/security/ (requires root)
#   make verify-log   — check audit log integrity

CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic \
          -fstack-protector-strong \
          -D_FORTIFY_SOURCE=2 \
          -fPIC \
          -O2
#
# Security-relevant compiler flags explained:
#   -fstack-protector-strong  : adds canaries to detect stack smashing (buffer overflow)
#   -D_FORTIFY_SOURCE=2       : enables glibc checks on string/memory functions
#   -fPIC                     : position-independent code (required for shared libs)
#   -Wall -Wextra -Wpedantic  : catch common mistakes at compile time

LDFLAGS = -lpam -lcrypto -lssl
SRCS    = src/pam_auth.c src/totp_engine.c src/security.c src/audit_log.c
OBJS    = $(SRCS:.c=.o)
TARGET  = pam_auth.so

$(TARGET): $(OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)
	@echo "Built $(TARGET)"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Standalone test binary (no PAM dependency — for unit testing)
test: src/totp_engine.c src/security.c src/audit_log.c tests/test_main.c
	$(CC) $(CFLAGS) -DSTANDALONE_TEST \
	    -o auth_test \
	    src/totp_engine.c src/security.c src/audit_log.c tests/test_main.c \
	    -lcrypto -lssl
	@echo "Built auth_test — run with: ./auth_test"

clean:
	rm -f src/*.o $(TARGET) auth_test

install: $(TARGET)
	@echo "Installing to /lib/security/ (requires root)"
	install -o root -g root -m 0644 $(TARGET) /lib/security/pam_auth.so
	mkdir -p /etc/auth_module
	mkdir -p /var/lib/auth_module
	chmod 700 /etc/auth_module /var/lib/auth_module
	@echo "Done. Edit /etc/pam.d/sshd to enable."

verify-log:
	@echo "Verifying audit log integrity..."
	@./auth_test --verify-log 2>&1 || echo "Tampering detected!"

.PHONY: clean install test verify-log
