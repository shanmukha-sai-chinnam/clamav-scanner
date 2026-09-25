#!/usr/bin/env bash
# ClamAV Sentinel - End-to-End (E2E) Integration Test Suite
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX_DIR="${SCRIPT_DIR}/test_sandbox"
QUARANTINE_DIR="${SANDBOX_DIR}/.quarantine"
AUDIT_LOG="${SANDBOX_DIR}/audit.jsonl"
PYTHON="${PYTHON:-python3}"

GREEN='\033[32m'
RED='\033[31;1m'
YELLOW='\033[33m'
CYAN='\033[36m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${BOLD}${CYAN}==============================================${RESET}"
echo -e "${BOLD}${CYAN}   ClamAV Sentinel - Live E2E Test Suite      ${RESET}"
echo -e "${BOLD}${CYAN}==============================================${RESET}"

# 1. Check if ClamAV daemon is responding
echo -e "\n${CYAN}[Stage 1] Verifying ClamAV Daemon Connectivity...${RESET}"
if ! "${PYTHON}" -c "
import sys; sys.path.insert(0, '${SCRIPT_DIR}/src')
from clamav_client import ClamAVClient
client = ClamAVClient()
if not client.ping():
    sys.exit(1)
print(f'Connected to: {client.version()}')
" 2>/dev/null; then
    echo -e "${YELLOW}ClamAV daemon not reachable. Attempting to start with 'clamav-sentinel up'...${RESET}"
    "${SCRIPT_DIR}/bin/clamav-sentinel" up
fi

# 2. Setup Sandbox
echo -e "\n${CYAN}[Stage 2] Preparing isolated test sandbox at ${SANDBOX_DIR}...${RESET}"
rm -rf "${SANDBOX_DIR}"
mkdir -p "${SANDBOX_DIR}" "${QUARANTINE_DIR}"

# 3. Launch Sentinel in background
echo -e "\n${CYAN}[Stage 3] Launching Sentinel background watcher...${RESET}"
"${PYTHON}" "${SCRIPT_DIR}/src/sentinel.py" \
    --watch-dir "${SANDBOX_DIR}" \
    --quarantine-dir "${QUARANTINE_DIR}" \
    --audit-log "${AUDIT_LOG}" &
SENTINEL_PID=$!

cleanup() {
    echo -e "\n${CYAN}[Cleanup] Tearing down test processes and sandbox...${RESET}"
    if kill -0 "${SENTINEL_PID}" 2>/dev/null; then
        kill "${SENTINEL_PID}" 2>/dev/null || true
        wait "${SENTINEL_PID}" 2>/dev/null || true
    fi
    # Restore permissions on quarantine dir before removing
    chmod -R 700 "${SANDBOX_DIR}" 2>/dev/null || true
    rm -rf "${SANDBOX_DIR}"
}
trap cleanup EXIT

# Wait 1.5s for watches to register
sleep 1.5

# Test 1: Benign File Creation
echo -e "\n${CYAN}[Test 1] Testing Benign File Creation...${RESET}"
echo "Hello, this is a legitimate document." > "${SANDBOX_DIR}/safe_doc.txt"
sleep 1.0

if [ ! -f "${SANDBOX_DIR}/safe_doc.txt" ]; then
    echo -e "${RED}FAIL: safe_doc.txt was incorrectly moved or deleted!${RESET}"
    exit 1
fi

if ! grep -q '"status": "CLEAN"' "${AUDIT_LOG}"; then
    echo -e "${RED}FAIL: Audit log does not record CLEAN status for safe_doc.txt${RESET}"
    cat "${AUDIT_LOG}"
    exit 1
fi
echo -e "${GREEN}✓ Test 1 Passed: Benign file scanned and verified clean.${RESET}"

# Test 2: Nested Subdirectory Monitoring
echo -e "\n${CYAN}[Test 2] Testing Recursive Subdirectory Monitoring...${RESET}"
mkdir -p "${SANDBOX_DIR}/deeply/nested/dir"
sleep 1.0
echo "Nested text file" > "${SANDBOX_DIR}/deeply/nested/dir/nested_file.txt"
sleep 1.0

if ! grep -q "nested_file.txt" "${AUDIT_LOG}"; then
    echo -e "${RED}FAIL: Recursive watch missed nested_file.txt${RESET}"
    exit 1
fi
echo -e "${GREEN}✓ Test 2 Passed: Recursive directory creation detected and scanned.${RESET}"

# Test 3: EICAR Malware Signature & Quarantine Isolation
echo -e "\n${CYAN}[Test 3] Testing Malware Detection & Quarantine (EICAR)...${RESET}"
# Write official EICAR test string
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "${SANDBOX_DIR}/malware.com"
sleep 1.5

# Verify file was removed from sandbox
if [ -f "${SANDBOX_DIR}/malware.com" ]; then
    echo -e "${RED}FAIL: malware.com is still present in watch directory!${RESET}"
    exit 1
fi

# Verify quarantined copy exists
QUARANTINED_COUNT=$(find "${QUARANTINE_DIR}" -name "*malware.com" | wc -l)
if [ "${QUARANTINED_COUNT}" -ne 1 ]; then
    echo -e "${RED}FAIL: Expected 1 quarantined file in ${QUARANTINE_DIR}, found ${QUARANTINED_COUNT}${RESET}"
    exit 1
fi

Q_FILE=$(find "${QUARANTINE_DIR}" -name "*malware.com" | head -n 1)
# Verify permissions are 000 (no permissions)
PERMS=$(stat -c "%a" "${Q_FILE}")
if [ "${PERMS}" != "0" ]; then
    echo -e "${RED}FAIL: Quarantined file permissions are ${PERMS}, expected 000!${RESET}"
    exit 1
fi

if ! grep -q '"status": "INFECTED"' "${AUDIT_LOG}"; then
    echo -e "${RED}FAIL: Audit log does not record INFECTED status!${RESET}"
    cat "${AUDIT_LOG}"
    exit 1
fi
echo -e "${GREEN}✓ Test 3 Passed: EICAR malware detected, quarantined with mode 000, and logged.${RESET}"

# Test 4: Exclusion Filters (.git ignored)
echo -e "\n${CYAN}[Test 4] Testing Exclusion Filters (.git ignored)...${RESET}"
mkdir -p "${SANDBOX_DIR}/.git"
echo "Git internal data" > "${SANDBOX_DIR}/.git/dummy.txt"
sleep 0.5

if grep -q "dummy.txt" "${AUDIT_LOG}"; then
    echo -e "${RED}FAIL: Sentinel scanned ignored file inside .git!${RESET}"
    exit 1
fi
echo -e "${GREEN}✓ Test 4 Passed: Ignored directory items bypassed properly.${RESET}"

echo -e "\n${BOLD}${GREEN}==============================================${RESET}"
echo -e "${BOLD}${GREEN}   All E2E Integration Tests Passed! (4/4)    ${RESET}"
echo -e "${BOLD}${GREEN}==============================================${RESET}"
