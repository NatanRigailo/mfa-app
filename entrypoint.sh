#!/bin/sh
set -e

# Fix /data ownership when volume is mounted with wrong permissions (e.g. pre-existing volume)
chown appuser:appgroup /data

exec su-exec appuser /app/mfa-app "$@"
