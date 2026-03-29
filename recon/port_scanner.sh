#!/bin/bash

TARGET=$1

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <IP>"
  exit 1
fi

echo "[+] Scanning $TARGET..."

for port in $(seq 1 65535); do
  timeout 0.5 bash -c "echo > /dev/tcp/$TARGET/$port" 2>/dev/null && \
  echo "[OPEN] Port $port"
done
