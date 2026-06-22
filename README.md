# gosh.ackinacki

Acki Nacki blockchain integration layer for GOSH.AI autonomous runtime.

Subscribes to block streams, filters messages, transforms to x402-compatible facts, manages multisig wallets, runs the [AI Registry SPC-token marketplace](#ai-registry-spc-token-marketplace), and persists agent state in [gosh.memory](https://github.com/Futurizt/gosh.memory).

Everything is exposed over an [MCP server](#calling-the-mcp-server-integrator-quickstart) — the integration interface for any host (e.g. gosh.pi).

## Architecture

`gosh-ackinacki` works over **two data planes** — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md):

- **Plane A (lean, default)** — chain read/write over the **Block Manager**'s
  HTTP/GraphQL API (`account`, `messages`, `/v2/messages`). Pure `reqwest` + the
  TVM SDK; no node, no MsQuic. This is everything a thin client needs.
- **Plane B (heavy, opt-in `--features block-stream`)** — your own indexer: a
  QUIC firehose from the **Block Keeper** nodes, decoded and filtered into facts.
  Pulls the `node` + `transport-layer` crates and **MsQuic**.

```
PLANE A (lean):  gosh-ackinacki ──HTTP──→ Block Manager  /graphql /v2/messages
                  reads · getters · events · signed writes · multisig · crypto

PLANE B (opt-in, --features block-stream):
  BK Nodes ──QUIC──→ transport ──→ decoder ──→ filter ──→ transform ──→ gosh.memory
                      (MsQuic)                  rules       facts        ingest API

MCP Server (port 8402) ←── agents call tools (read/write/payment)
SwarmRoot (on-chain)   ──→ deploys child multisig wallets within a DApp ID
gosh.memory            ←── object/secrets/facts (full-agent mode)
```

## Using `gosh-ackinacki` as a library

This crate is **both a binary and a library** (`src/lib.rs`, importable as
`gosh_ackinacki`). To consume the chain primitives from another crate, depend on
it by git tag with the **lean default** (no node / no MsQuic):

```toml
[dependencies]
gosh-ackinacki = { git = "https://github.com/<owner>/gosh.ackinacki", tag = "vX.Y.Z", default-features = false }
```

Then use the public modules directly — for example a read + a signed write
(Plane A, HTTP only):

```rust
use gosh_ackinacki::config::NetworkConfig;
use gosh_ackinacki::airegistry::getter::{AccountReader, AccountOrigin};

let net = NetworkConfig::shellnet();
let reader = AccountReader::new(reqwest::Client::new(), &net.send_endpoint);
let snap = reader
    .fetch(&net.airegistry, "0:<hex>", &AccountOrigin::SelfOriginating)
    .await?;            // account state via the Block Manager GraphQL
```

Useful Plane-A entry points: `airegistry::getter` (`AccountReader`,
`read_events`), `airegistry::run::GetterRunner` (local getters), `airegistry::deploy`
/ `airegistry::calls` (encode deploy / calls), `wallet::query::send_message`
(broadcast), `wallet::transact` (multisig submit/confirm/send encoders),
`wallet::contracts` (multisig ABI/TVC), `client::crypto` (X25519), and
`config::NetworkConfig`. Add `features = ["block-stream"]` only if you want the
BK firehose indexer (`transport` / `decoder` / `filter::engine::process_block` /
`transform`).

## Quick Start

### Prerequisites

- Rust 1.86+ (builds on stable).
- **Only for `--features block-stream` (the Plane-B indexer):** a **working**
  `cmake` (≥ 3.20) and `libnuma-dev` — the `transport-layer` dependency pulls
  **MsQuic**, whose `build.rs` compiles a bundled `quictls` (an OpenSSL fork) via
  cmake. A broken or partial cmake produces an **incomplete `libcrypto`** and the
  binary then fails to *link* (see Troubleshooting below). `clang`/`llvm` and
  `pkg-config` are also required by the MsQuic build. **The lean default build
  needs none of this.**
- A running gosh.memory instance (>= dev with namespace + swarm-agent auth)
  — **only for the full agent mode**; the AI Registry read-only mode needs no
  gosh.memory (see [Runtime modes](#runtime-modes)).
- A namespace admin who has issued a swarm-agent join bundle for this agent
  (full agent mode only).

### Runtime modes

`gosh-ackinacki` is a **Memory-backed full blockchain-integration agent by
default** — not a thin proxy. It runs in one of two modes:

- **Full agent mode** (default) — `gosh.memory` is **required**. Block-stream
  fact ingestion, wallet custodian keys, sealed namespace secrets, wallet
  policies, and the object-store pointer cache all live in gosh.memory. Needs
  bootstrap/auth.
- **AI Registry read-only mode** (`--read-only`) — `gosh.memory` is **not
  required**. The blockchain is the source of truth; the service exposes only
  the chain-first AI Registry read tools (`airegistry_resolve_model`,
  `_get_manifest`, `_get_lot`, `_get_entitlement`, `_list_marketplace`, and
  `call_contract` getters). `tools/list` advertises **only** this subset — it is
  an honest capability contract — and any other tool is rejected. Memory-backed
  tools (wallets / secrets / policies / fact ingest) thus return an explicit
  **"not available in read-only mode"** / **"Memory-backed mode required"** error.
  No bootstrap, auth, BK/DNS, or running gosh.memory is needed — anyone can run
  it against the network (a backend, or a user on a laptop) to read the
  marketplace:

  ```bash
  gosh-ackinacki --read-only --network shellnet
  ```

### Build

The `block-stream` Cargo feature gates the heavy Plane-B indexer (the `node` /
`transport-layer` crates + MsQuic). It is **off by default**, so the default
build is lean and needs none of the cmake/MsQuic toolchain below.

```bash
# Lean (default): Plane A only — chain client, multisig, crypto, MCP
# read/write/payment. No node, no MsQuic. Fast build.
cargo build --release --bin gosh-ackinacki

# Full agent: + Plane B — the BK block-firehose indexer into gosh.memory.
# Pulls node/transport/MsQuic (needs the cmake/libnuma toolchain below).
cargo build --release --bin gosh-ackinacki --features block-stream

# verify it links + starts:
./target/release/gosh-ackinacki --help
```

> The `--read-only` and `--stateless-payments` services use only Plane A — build
> them lean. Full-agent block ingestion requires `--features block-stream`; the
> MsQuic prerequisites below apply **only** to that build.

#### Troubleshooting: `undefined symbol: ossl_der_oid_*` at link time

If the link step fails with errors like:

```text
rust-lld: error: undefined symbol: ossl_der_oid_id_X25519
>>> referenced by der_ecx_key.c  (… in archive libmsquic-*.rlib)
rust-lld: error: undefined symbol: ossl_der_oid_ecdsa_with_SHA224
```

this is **not** a source bug — these `ossl_der_oid_*` symbols are *internal*
OpenSSL 3 symbols that must come from the `quictls` that MsQuic builds for
itself. The error means MsQuic's bundled crypto was built **incompletely**,
almost always because the cmake used to build it was broken or mismatched
(a stale/partial `~/.local/bin/cmake`, a missing toolchain). The current PR
head links + runs cleanly with a stock toolchain (cmake 3.28, OpenSSL 3.0.13).
To fix the environment, ensure a real cmake is first on `PATH` and rebuild
MsQuic from scratch:

```bash
which cmake && cmake --version   # must be a real cmake ≥ 3.20
cargo clean -p msquic            # drop the bad MsQuic/quictls build
cargo build --release --bin gosh-ackinacki
```

### One-time bootstrap

ackinacki authenticates as a **swarm-agent** against gosh.memory using a
Bearer principal token. Before first start, the namespace admin must:

1. Create a namespace and swarm in gosh.memory, add `agent:ackinacki` as a
   `read_write` member, and issue a `memory_swarm_agent_token_issue` for it.
2. Pre-seed any required namespace secrets (e.g. the SwarmRoot owner key) via
   `memory_namespace_secret_set` — see [Namespace Secrets](#namespace-secrets) below.
3. Hand the agent a bootstrap file:

```json
{
  "join_token": "gosh_join_<base64url-encoded JSON>",
  "secret_key": "<base64 of a fresh 32-byte X25519 private key>"
}
```

The `join_token` decodes to `{"url", "principal_token", "transport_token"?,
"principal_id"?, "fingerprint"?, "ca"?}` and must include a non-empty
`principal_token` — a transport-only token is rejected.

On the first start, ackinacki reads the bootstrap, **persists** the auth
state to `~/.gosh-ackinacki/memory-auth.json` (mode `0o600`, atomic write),
**deletes** the bootstrap file, generates an X25519 keypair in memory, and
registers its public key with gosh.memory.

### Run (first start)

```bash
gosh-ackinacki \
  --network shellnet \
  --bk-nodes shellnet0.ackinacki.org:10000,shellnet1.ackinacki.org:10000 \
  --bootstrap-file /path/to/bootstrap.json \
  --memory-key <namespace-key> \
  --swarm-id <swarm-id> \
  --agent-id ackinacki
```

### Run (subsequent starts)

The persisted `memory-auth.json` provides the Bearer token; the X25519 secret
must be supplied via env (it is **not** persisted to disk) so the agent can
decrypt sealed namespace secrets:

```bash
GOSH_ACKINACKI_X25519_SECRET=<base64-of-32-bytes> \
gosh-ackinacki \
  --network shellnet \
  --memory-key <namespace-key> \
  --swarm-id <swarm-id>
```

### Configuration

| Arg | Env | Default | Description |
|-----|-----|---------|-------------|
| `--network` | `GOSH_ACKINACKI_NETWORK` | `shellnet` | shellnet / mainnet / custom |
| `--bind` | `GOSH_ACKINACKI_BIND` | `127.0.0.1:8402` | MCP server bind address |
| `--read-only` | `GOSH_ACKINACKI_READ_ONLY` | `false` | AI Registry read-only mode — no gosh.memory; serves only chain-first read tools ([Runtime modes](#runtime-modes)) |
| `--bk-nodes` | `GOSH_ACKINACKI_BK_NODES` | (from network) | QUIC endpoints, comma-separated (full mode only) |
| `--send-endpoint` | `GOSH_ACKINACKI_SEND_ENDPOINT` | (from network) | HTTP endpoint for sending messages |
| `--airegistry-super-root` | `GOSH_AIREGISTRY_SUPER_ROOT` | (none) | Default AI Registry SuperRoot for this network; lets `airegistry_list_marketplace` run without a `super_root_address` arg |
| `--memory-url` | `GOSH_MEMORY_URL` | `http://127.0.0.1:8000` | gosh.memory base URL (overridden by `memory-auth.json` after bootstrap) |
| `--memory-key` | `GOSH_MEMORY_KEY` | `default` | gosh.memory namespace key |
| `--memory-transport-token` | `GOSH_MEMORY_TRANSPORT_TOKEN` | (none) | Optional perimeter `x-server-token` for gosh.memory |
| `--agent-id` | `GOSH_AGENT_ID` | `ackinacki` | Agent id (data selector — does not grant identity) |
| `--swarm-id` | `GOSH_SWARM_ID` | `default` | Swarm id (data selector) |
| `--bootstrap-file` | `GOSH_ACKINACKI_BOOTSTRAP` | (none) | One-time bootstrap JSON; consumed and deleted |
| `--memory-auth-path` | `GOSH_ACKINACKI_MEMORY_AUTH_PATH` | `~/.gosh-ackinacki/memory-auth.json` | Where to persist the Bearer principal token |
| `--server-token` | `GOSH_ACKINACKI_SERVER_TOKEN` | (auto-generated) | MCP perimeter token (`x-server-token` on the local `/mcp` surface) |
| `--filter-config` | `GOSH_ACKINACKI_FILTER` | (none) | JSON filter rules file |
| _(env only)_ | `GOSH_ACKINACKI_X25519_SECRET` | (required on restart) | Base64 32-byte X25519 private key for sealed-secret decryption |

The local MCP server token is saved to `~/.gosh-ackinacki/token` (`0o600`).

## MCP Tools

### Block Stream

| Tool | Description |
|------|-------------|
| `subscribe_address` | Subscribe to messages from/to an address |
| `unsubscribe_address` | Remove address subscription |
| `list_subscriptions` | List current filter rules |
| `register_abi` | Register contract ABI for method decoding |

### Wallet Management

| Tool | Description |
|------|-------------|
| `create_keys` | Generate Ed25519 keypair for a wallet custodian (persists via `memory_object_upsert`) |
| `get_wallet_status` | Check if all custodian keys are present |
| `deploy_wallet` | Deploy a 2-of-3 multisig wallet via SwarmRoot |
| `send_transaction` | Submit transaction (requires 2nd confirmation) |
| `confirm_transaction` | Confirm pending multisig transaction |

#### Prerequisites for `deploy_wallet`

1. **Namespace admin** has pre-seeded the SwarmRoot owner private key as a
   namespace secret:
   `memory_namespace_secret_set(key=<namespace>, name="swarm_root:<addr>:owner:privkey", value=<hex-32-bytes>)`.
2. Agent has created the three wallet custodian keys with `create_keys` for
   roles `agent`, `controller`, `owner`.
3. Agent calls `deploy_wallet` with `wallet_id` and `swarm_root_address`.

The SwarmRoot owner key is separate from wallet custodian keys: it controls
the SwarmRoot factory contract and authorizes child wallet deploys. It is
delivered to the agent via X25519 sealed-box on each `deploy_wallet` call —
the agent never persists or relays the plaintext.

#### Where agent state is stored

| Data | Backing |
|------|---------|
| Wallet privkeys / pubkeys / address / swarm_root metadata | gosh.memory `memory_object_upsert` (agent-writable, persistent across restarts, ACL bound to this agent principal) |
| SwarmRoot owner privkey (and any other admin-managed secret) | gosh.memory namespace secret store, delivered via REST sealed-box (`/api/v1/agent/secrets/resolve`, GMS2 envelope, X25519 + HKDF-SHA256 + AES-256-GCM) |
| Block-stream facts, wallet policies | gosh.memory `memory_ingest_asserted_facts` / `memory_query` |

### Policies

| Tool | Description |
|------|-------------|
| `set_wallet_policy` | Set spending limits and allowed destinations |
| `get_wallet_policy` | Query wallet policy from gosh.memory |

Policy enforcement checks `max_tx_amount`, `allowed_destinations`,
`blocked_destinations`, and `frozen` tier before every `send_transaction`.
Policy lookup failures reject the transaction (fail-closed).

### AI Registry (SPC token marketplace)

An on-chain marketplace for AI-model API-usage tokens, built on the airegistry
contracts (`SuperRoot → RootModel → TokenContract → ManifestMetadata`). A
**creator** (model vendor) lists a model and sells usage tokens; a **consumer**
buys/consumes them under a governed budget. **The blockchain is the only source
of truth** — see [Design & data model](#design--data-model) below.

**Generic**

| Tool | Description |
|------|-------------|
| `call_contract` | Run an ABI getter (read), or — with a `signer_ref` — a signed external call (write) |
| `deploy_contract` | Deterministic stateInit deploy (signed by `signer_ref`), Giver-funded on shellnet |

**Creator** — the model vendor, signing with a `signer_ref` (object-store key or namespace-secret pointer):

| Tool | Description |
|------|-------------|
| `airegistry_register_model` | Deploy a RootModel for `owner_pubkey` (self-registers with SuperRoot) |
| `airegistry_set_manifest` | Store the **full canonical package on-chain** in ManifestMetadata as ≤32 KB indexed chunks (`setApiSchemaChunk`); every chunk is confirmed on-chain and the reassembled sha256 is verified before success |
| `airegistry_get_manifest` | Read the full package straight from chain (`getApiSchemaChunkCount` + `getApiSchemaChunk` per index, concatenated), sha256-verified — **no memory needed** |
| `airegistry_create_token_lot` | Deploy a TokenContract token lot (price, fee, supply, cap). `package_sha256` is **off-chain** pointer/cache metadata only (Memory object-store, when that path is used) — **not** TokenContract on-chain state; verify package integrity by reading `ManifestMetadata` via `airegistry_get_manifest` |
| `airegistry_bill_session` | `consumeSession` — bill delivered usage straight into `sellerOwed` (first call up to `maxReservedSessions`, then exactly 1/call) |
| `airegistry_withdraw_shell` | Pull accumulated ECC[2] SHELL revenue |
| `airegistry_replenish` / `airegistry_set_endpoint` / `airegistry_destroy_lot` | Top up supply / change endpoint / destroy a settled lot |
| `airegistry_get_lot` | Read a lot's counters / config / buyer / shell balance |
| `airegistry_deploy_super_root` | Deploy a SuperRoot (usually host-provided) |

**Consumer** — acts through 3-custodian `SwarmMultisigWallet`s (treasury `reqConfirms=2`, operational `reqConfirms=1`), signing with named wallet custodian keys; rate-limited + policy-gated:

| Tool | Description |
|------|-------------|
| `airegistry_resolve_model` | Resolve a RootModel + TokenContract address (+ endpoint) from owner/seller/nonce |
| `airegistry_deploy_buyer` | Deploy a 1-of-3 operational wallet via SwarmRoot (`create_keys` ×3 + `deploy_wallet`) |
| `airegistry_fund_buyer` | Governed treasury→operational budget top-up (2-of-3 queues; returns `transaction_id` for the 2nd custodian) |
| `airegistry_buy_tokens` | Operational wallet buys tokens by forwarding ECC[2] SHELL to `buyTokens()` |
| `airegistry_cancel` | Buyer stop-loss: `cancel()` refunds the unconsumed `reservedTokens` to the operational wallet and releases the lot (seller keeps already-billed `sellerOwed`; no caller-supplied payout) |
| `airegistry_get_entitlement` | Read the buyer's `reserved / consume_calls / seller_owed` + endpoint |

### Design & data model

**The package lives on-chain — there is no off-chain package store.**
The full canonical package (its bytes, verbatim) is stored in the
`ManifestMetadata` contract as a **mapping of indexed chunks**
(`mapping(uint32 => string)`). The package is split into ≤32 KB pieces written at
indices `0, 1, 2, …` via `setApiSchemaChunk(idx, chunk)` (the constructor's
`firstChunk` seeds index 0), and `deleteApiSchemaChunk(idx)` clears one. Each
write is **O(1)** — it touches only its own chunk, so there is no growing-string
gas cap and packages of any size fit. A reader gets the chunk count from
`getApiSchemaChunkCount()` and stitches `getApiSchemaChunk(0..count)` back
together. Storing packages in an external store (a "memory" service or any other)
would re-introduce a **centralization point and a data-availability problem** —
*which* store, and why would a chain user have access to it? A blockchain user
has the contract, and the contract has everything. `package_sha256` is the
package's **integrity hash**, verified after an on-chain read — not a pointer to
anything off-chain.

**One package, many token offers.** A model's package (`ManifestMetadata`) is
derived from `(owner_pubkey, root_model)` — **one package per model** — and it
has **no self-destruct**: the package is permanent and always readable. A token
lot (`TokenContract`) is derived from `(seller_pubkey, nonce)`, so a seller can
deploy **as many concurrent offers for the same package as they want** (one per
`nonce`), and a lot **can** be retired (`destroy`, once nothing is reserved).
The package is forever; a token offer exists only while the seller keeps it. A
model with no active lot is still discoverable and readable — it simply isn't
purchasable until a lot is (re)deployed or replenished.

**Discovery is event-driven.** There is no global "list all" call on a
blockchain. `airegistry_list_marketplace` enumerates the marketplace by scanning
the on-chain registration **events** — `RootRegistered` (models),
`ManifestRegistered` (packages), and `TokenContractRegistered` (lots) — straight
from the event log, with no Memory and no getter-over-BOC: pass
`super_root_address` to list its models + manifests, or `root_model_address` to
list that model's token lots. `super_root_address` is **optional** — when omitted
the service's configured default SuperRoot (`--airegistry-super-root` /
`GOSH_AIREGISTRY_SUPER_ROOT`) is used and echoed back in the response, so a
backend indexer can sync without knowing the deployment's address. It is a real
**sync contract**, not a recent
peek: events come back oldest-first with stable identity (`message_id`, `lt`) and
a per-event `cursor`, plus `page_info { has_more, end_cursor, scanned_messages }`.
A backend indexer pages forward with `first` + `after` (the prior `end_cursor`),
persists `end_cursor` as a checkpoint, and knows it has caught up when `has_more`
is false — so initial sync is provable and incremental sync resumes from the
checkpoint. A known `SuperRoot + owner/seller/nonce` is also resolved directly by
deterministic derivation (`resolve_model`, `get_manifest`, `get_lot`). The event
log *is* the catalog; the chain is its source of truth.

**Blockchain-first reads.** AI Registry reads (discovery, manifest/package, lot
config/counters/entitlement) are authoritative from chain and need no `gosh.memory`
— anyone can run the service against the network (a backend, or a user on a
laptop) and read the marketplace. `gosh.memory` is only involved in the wallet/
write plane: custodian key storage, sealed-secret resolution, wallet policies,
block-fact ingestion, and optional best-effort pointer caching. A pointer-cache
miss never blocks an on-chain result.

**Scope.** This layer is the **economic + registry plane on-chain** (packages,
lots, payments, governance). What a higher-level host bills, which packages a
subscription "includes", and runtime lifecycle are **the host backend's
concern**, not this layer — integrators call `gosh-ackinacki` as a service over
MCP rather than vendoring it. On-chain reverts surface as readable `ERR_*`
messages.

## Calling the MCP server (integrator quickstart)

The MCP surface **is** the integration interface — any language can bind to it.
It is JSON-RPC 2.0 over HTTP at `POST /mcp` on the bind address (default
`127.0.0.1:8402`), authenticated by the `x-server-token` header (the token is at
`~/.gosh-ackinacki/token`). `/health` is public.

Methods: `initialize`, `tools/list`, `tools/call`. A `tools/call` result is
wrapped as `{ "content": [{ "type": "text", "text": "<json string>" }], "isError": bool }`
— parse `content[0].text` as JSON for the tool's actual output.

**Discover tools:**

```bash
curl -s http://127.0.0.1:8402/mcp \
  -H "x-server-token: $(cat ~/.gosh-ackinacki/token)" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

**Call a tool** (consumer buys API-usage tokens):

```bash
curl -s http://127.0.0.1:8402/mcp \
  -H "x-server-token: $(cat ~/.gosh-ackinacki/token)" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
        "name":"airegistry_buy_tokens",
        "arguments":{"oper_wallet_id":"buyer1","signer_role":"agent",
                     "token_contract_address":"0:<token>","shell_amount":"5000"}}}'
```

**How a host (e.g. gosh.pi) adds a gosh.ackinacki command:**

1. Ensure a bootstrapped `gosh-ackinacki` is running (MCP on `:8402`, token on disk).
2. Add it as an MCP server (HTTP transport + the `x-server-token` header), or POST
   raw JSON-RPC as above.
3. Map a user command → a `tools/call`, then parse `content[0].text`. Suggested
   commands:
   - **creator:** `register-model` → `airegistry_register_model`; `publish-schema` →
     `airegistry_set_manifest`; `list-for-sale` → `airegistry_create_token_lot`;
     `bill` / `withdraw` → `airegistry_bill_session` / `airegistry_withdraw_shell`.
   - **consumer:** `resolve` → `airegistry_resolve_model`; `deploy-budget-wallet` →
     `airegistry_deploy_buyer`; `fund-budget` → `airegistry_fund_buyer`; `buy` →
     `airegistry_buy_tokens`; `cancel` → `airegistry_cancel`;
     `entitlement` → `airegistry_get_entitlement`.

`airegistry_deploy_*` / `create_*` need a creator `signer_ref` (a pointer to the
seller key the host pre-seeded) and, on shellnet, fund derived addresses via the
Giver; consumer spend tools need the wallet custodian keys (`create_keys` →
`airegistry_deploy_buyer`) and a delegated-budget policy (`set_wallet_policy`).

## Wallet Architecture

### 2-of-3 Multisig

Each swarm wallet uses `UpdateCustodianMultisigWallet` with 3 custodians.
Any 2 of 3 signatures execute a transaction.

| Role | Purpose |
|------|---------|
| Agent | Submits transactions |
| Controller | Confirms or blocks transactions |
| Owner | Recovery, key rotation |

### SwarmRoot (DApp ID)

`SwarmRoot` is a factory contract that deploys child wallets via internal
messages. All child wallets inherit the SwarmRoot's DApp ID, enabling
gasless internal transactions via `gosh.mintshell()` from a shared
`DappConfig`.

```
Owner deploys SwarmRoot (external msg) → DApp ID created
    ↓
SwarmRoot.setWalletCode(code)
    ↓
SwarmRoot.createDappConfig(dappRoot, shellAmount) → funds gas pool
    ↓
SwarmRoot.deployWallet(pubkeys, reqConfirms) → child wallet (internal msg)
    ↓
Child wallets transact gaslessly within DApp ID
```

### Funding

- **VMSHELL** cannot cross DApp boundaries (zeroed on cross-DApp transfer).
- **SHELL** (ECC currency 2) can cross DApp boundaries.
- Use `flag: 17` (1 + 16) to send SHELL to uninit accounts (auto-converts to VMSHELL).
- Within a DApp ID, wallets call `gosh.mintshell()` to get gas from DappConfig.

## Namespace Secrets

The agent can read but **cannot write** namespace secrets — this is by
design. Namespace admins seed secrets up-front via gosh.memory's
`memory_namespace_secret_set` MCP tool; the agent fetches them on demand
via X25519 sealed-box (`POST /api/v1/agent/secrets/resolve`). All
delivery is end-to-end encrypted to the agent's registered X25519 public
key; plaintext never lives on disk.

To seed the SwarmRoot owner key (admin step, done once per SwarmRoot):

```
memory_namespace_secret_set(
  key="<namespace>",
  name="swarm_root:0:<addr-hex>:owner:privkey",
  value="<32-byte hex>"
)
```

## x402 Compatibility

Blockchain events are transformed to [x402](https://x402.org)-compatible facts:

```json
{
  "fact": "0:abc sent 5.00 EVER to 0:def calling transfer() on Acki Nacki",
  "kind": "fact",
  "metadata": {
    "x402_version": 2,
    "x402_network": "ackinacki",
    "x402_transaction": "block:12345:lt:6789",
    "x402_payer": "0:abc...",
    "x402_payee": "0:def...",
    "x402_amount": "5000000000",
    "ackinacki_event_type": "payment",
    "ackinacki_method": "transfer",
    "ackinacki_block_seq_no": 12345
  }
}
```

Event types: `payment`, `deploy`, `call`, `confirm`, `event`, `dapp_config`, `message`.

## E2E Tests

```bash
# Cross-swarm payments (requires shellnet wallets)
AGENT_ALPHA_SECRET=... CTRL_ALPHA_SECRET=... \
AGENT_BETA_SECRET=... CTRL_BETA_SECRET=... \
cargo run --example e2e_payments

# Event-driven marketplace via Courier + gosh.memory
cargo run --example e2e_courier

# SwarmRoot: deploy wallets + gasless intra-swarm payments
OWNER_SECRET=... AGENT_ALPHA_SECRET=... CTRL_ALPHA_SECRET=... \
cargo run --example e2e_swarm_wallets

# Full gosh.memory swarm-agent integration (auth bootstrap → namespace
# secret resolve → object_store roundtrip → MCP tool dispatch). Requires
# a live gosh.memory instance.
GOSH_MEMORY_E2E_URL=http://127.0.0.1:18765 \
GOSH_MEMORY_E2E_ADMIN_TOKEN=<bootstrap-admin-token> \
GOSH_MEMORY_E2E_TRANSPORT_TOKEN=<server-token> \
cargo test --test e2e_memory -- --nocapture
```

## Project Structure

```
src/
  transport/        QUIC subscriber + connection pool (from ackinacki BM)
  decoder/          Block deserialization + dedup filter
  filter/           Rules engine + ABI decode
  transform/        x402-compatible fact generation
  wallet/           Deploy, transact, query, policy, contracts
  airegistry/       SPC token marketplace: abi, deploy/derive, calls, getters,
                    events, signer_ref, object-store data model, error mapping
  mcp/              MCP server + 29 tools (block-stream, wallet, airegistry)
  client/
    auth.rs           JoinToken + memory-auth.json persistence
    crypto.rs         X25519 sealed-box (GMS2) decryption
    mcp_http.rs       MCP transport (initialize, session, SSE)
    memory.rs         Fact ingest + wallet policy (memory_ingest_asserted_facts, memory_query)
    object_store.rs   Persistent agent state (memory_object_upsert/get/list)
    sealed_secrets.rs Namespace secret resolve (REST sealed-box)
  config.rs         Network + CLI config
  state.rs          Shared AppState
  main.rs           Startup wiring + bootstrap flow

contracts/
  swarm/            SwarmRoot + SwarmMultisigWallet (Solidity)
  *.abi.json        Compiled ABIs
  *.tvc             Compiled contract images

examples/
  e2e_courier.rs        Full E2E with Courier SSE + gosh.memory
  e2e_payments.rs       Cross-swarm payments on shellnet
  e2e_swarm_wallets.rs  SwarmRoot wallet deploy + gasless payments
  deploy_swarmroot.rs   Deploy SwarmRoot + DappConfig

tests/
  e2e_memory.rs     Live-gosh.memory integration test (skipped without env)
```

## Security

- gosh.memory client uses Bearer **principal token** (Authorization header)
  plus an optional **transport token** (`x-server-token`) for the perimeter.
- Local MCP server authenticated via `x-server-token` header (constant-time comparison).
- CORS deny-all.
- Rate limiting: 10 tx/min per wallet.
- Policy enforcement fail-closed (rejects on memory errors).
- `validate_wallet_id`: alphanumeric + hyphen/underscore only.
- `validate_signer_role`: enum (agent/controller/owner).
- Tokens saved to file with `0o600` permissions; X25519 private key lives only in process memory (re-supplied via `GOSH_ACKINACKI_X25519_SECRET` on restart or re-bootstrap).

## License

MIT

Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
