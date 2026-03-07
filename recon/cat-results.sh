#!/bin/bash

# Usage
# ./cat-results.sh <target-ip>

TARGET=$1
DIR="recon_$TARGET"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip>"
    exit 1
fi

echo "======================================="
echo " OSCP Recon Results for $TARGET"
echo "======================================="
echo

# ---------------------------
# NMAP RESULTS
# ---------------------------
echo "########## NMAP OPEN PORTS ##########"
grep open $DIR/nmap/service_scan.nmap
echo

# ---------------------------
# SEARCHSPLOIT
# ---------------------------
echo "########## SEARCHSPLOIT ##########"
cat $DIR/searchsploit/searchsploit_by_service.txt
echo

# ---------------------------
# WEB TECH
# ---------------------------
echo "########## WHATWEB ##########"
cat $DIR/web/whatweb_* 2>/dev/null
echo

# ---------------------------
# GOBUSTER
# ---------------------------
echo "########## GOBUSTER ##########"
cat $DIR/web/gobuster_* 2>/dev/null
echo

# ---------------------------
# FFUF COMMANDS
# ---------------------------
echo "########## FFUF COMMANDS ##########"
cat $DIR/web/ffuf_* 2>/dev/null
echo

# ---------------------------
# NOTES
# ---------------------------
echo "########## MANUAL CHECKLIST ##########"
cat $DIR/notes/manual-checks.txt
echo

echo "======================================="
echo " End of Results"
echo "======================================="
