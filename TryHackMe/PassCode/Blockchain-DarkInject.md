# Blockchain — DarkInject

## Overview

| Parameter | Value |
|-----------|-------|
| Platform | TryHackMe |
| Room | Blockchain |
| Category | Web3 / Smart Contract Exploitation |
| Difficulty | Easy |
| Tools Used | curl, jq, Foundry (cast) |

## Objective

Make the `isSolved()` function of a deployed smart contract return `true`.

## Reconnaissance

### Getting Challenge Data

The challenge provides an API endpoint with all necessary information:

```bash
RPC_URL=http://<TARGET_IP>:8545
API_URL=http://<TARGET_IP>

PRIVATE_KEY=$(curl -s ${API_URL}/challenge | jq -r ".player_wallet.private_key")
CONTRACT_ADDRESS=$(curl -s ${API_URL}/challenge | jq -r ".contract_address")
PLAYER_ADDRESS=$(curl -s ${API_URL}/challenge | jq -r ".player_wallet.address")
```

API response revealed:
- Player wallet with 1.0 ETH balance
- Contract address
- RPC endpoint on port 8545 (standard Ethereum JSON-RPC)

### Analyzing the Contract Bytecode

Since no source code was provided, we extracted the bytecode:

```bash
cast code $CONTRACT_ADDRESS --rpc-url $RPC_URL
```

From the bytecode, four function selectors were identified by locating `PUSH4` opcodes (`0x63`) in the dispatcher section:

| Selector | Function |
|----------|----------|
| `0x6198e339` | `unlock(uint256)` |
| `0x64d98f6e` | `isSolved()` |
| `0xf9633930` | `getFlag()` |
| `0xfbf552db` | `hint()` |

Selectors were resolved using:

```bash
cast 4byte 0x6198e339  # unlock(uint256)
cast 4byte 0x64d98f6e  # isSolved()
cast 4byte 0xf9633930  # getFlag()
cast 4byte 0xfbf552db  # hint()
```

## Vulnerability Analysis

### Reading the Hint

```bash
cast call $CONTRACT_ADDRESS "hint()(string)" --rpc-url $RPC_URL
# Output: "The code is 333"
```

### Reading Contract Storage

In Ethereum, **all storage is publicly readable**, even variables declared as `private` in Solidity. The `private` keyword only prevents other contracts from accessing the variable through a function call — it does not hide data on the blockchain.

```bash
cast storage $CONTRACT_ADDRESS 0 --rpc-url $RPC_URL
# 0x54484d7b776562335f6834636b316e675f636f64657d0000000000000000002c
# (encoded flag string)

cast storage $CONTRACT_ADDRESS 1 --rpc-url $RPC_URL
# 0x0000000000000000000000000000000000000000000000000000000000000000
# (solved = false)

cast storage $CONTRACT_ADDRESS 2 --rpc-url $RPC_URL
# 0x000000000000000000000000000000000000000000000000000000000000014d
# 0x14d = 333 in decimal — the secret unlock code

cast storage $CONTRACT_ADDRESS 3 --rpc-url $RPC_URL
# 0x54686520636f646520697320333333000000000000000000000000000000001e
# (hint string: "The code is 333")
```

The "secret" code `333` was stored in **storage slot 2** as `0x14d` (hex) = `333` (decimal).

## Exploitation

### Unlocking the Contract

```bash
cast send $CONTRACT_ADDRESS "unlock(uint256)" 333 \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --legacy
```

> Note: The `--legacy` flag was required because the node did not support EIP-1559 transaction format.

Transaction returned `status: 1 (success)`.

### Verifying Solution

```bash
cast call $CONTRACT_ADDRESS "isSolved()(bool)" --rpc-url $RPC_URL
# Output: true
```

### Retrieving the Flag

```bash
cast call $CONTRACT_ADDRESS "getFlag()(string)" --rpc-url $RPC_URL
# Output: "THM{web3_h4ck1ng_code}"
```

## Key Takeaways

1. **Blockchain storage is never private.** Any data stored on-chain can be read by anyone using tools like `cast storage`. The `private` keyword in Solidity is a visibility modifier for contracts, not an encryption mechanism.

2. **Bytecode analysis reveals function signatures.** Even without source code, function selectors can be extracted from bytecode and resolved via public databases (`cast 4byte`, 4byte.directory).

3. **Foundry (`cast`) is the Swiss Army knife for blockchain interaction.** Key commands: `cast call` (read), `cast send` (write), `cast storage` (read raw storage), `cast code` (get bytecode), `cast 4byte` (resolve selectors).

## Flag

`THM{web3_h4ck1ng_code}`
