<!-- Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd. -->
<!-- SPDX-License-Identifier: MIT -->

# Architecture: two data planes, one crate

`gosh-ackinacki` talks to an Acki Nacki network over **two independent planes**.
Understanding the split is the key to depending on this crate as a library: the
lean plane needs nothing but HTTP; the heavy plane pulls a blockchain node and a
native QUIC stack.

```
                         ┌──────────────────────────────────────────┐
   PLANE A (lean)        │  Block Manager (BM)                       │
   read / write          │  https://<network>.ackinacki.org         │
   over HTTP             │   /graphql      account(account_id,dapp_id)
   — no node, no MsQuic  │   /v2/messages  (signed BOC writes)       │
                         │   /v2/account                             │
                         └──────────────────────────────────────────┘
                                    ▲ HTTP (reqwest)
                                    │
   ┌────────────────────────────────┴───────────────────────────────┐
   │ gosh-ackinacki                                                  │
   │   airegistry::getter  AccountReader.fetch  → BOC                │
   │   airegistry::run     GetterRunner         → local TVM getter   │
   │   airegistry::getter  read_events          → account.messages   │
   │   wallet::query       send_message         → POST /v2/messages  │
   │   airegistry / wallet / client::crypto / mcp                    │
   └────────────────────────────────┬───────────────────────────────┘
                                    │ QUIC (MsQuic)         PLANE B (heavy)
                                    ▼                       own indexer
                         ┌──────────────────────────────────────────┐
                         │  Block Keeper (BK) nodes                  │
                         │  <network>N.ackinacki.org:10000           │
                         │  raw block firehose                       │
                         └──────────────────────────────────────────┘
       transport::pool → decoder::block → filter::engine::process_block
                       → transform::to_fact → MemoryClient::ingest_facts
```

## Plane A — chain read/write via the Block Manager (lean, default)

The **Block Manager (BM)** already indexed the chain and exposes it over HTTP:

- **Reads** — `AccountReader::fetch` queries GraphQL `account(account_id, dapp_id)`
  for the account BOC, then `GetterRunner::run_getter` runs the ABI getter
  **locally** over that BOC (`tvm_client` `run_tvm`). We never poll getters in a
  loop.
- **Events** — `AccountReader::read_events` reads GraphQL `account.messages`
  (ext-out / `msg_type == 2`) and decodes them; this is the basis for marketplace
  discovery and an address event feed.
- **Writes** — `wallet::query::send_message` posts a signed BOC to `/v2/messages`
  with `account_id` / `dapp_id` routing.

This plane is **pure `reqwest` + the TVM SDK**. It pulls **no** `node`, **no**
`transport-layer`, **no** MsQuic. It is everything a thin client needs:
AI Registry reads, getters, signed writes, the multisig encoders, and crypto.

> The typed **`gosh_ackinacki::sdk`** facade — `ChainClient` (account/balances,
> getters, signed `call`/`deploy`, `chain_liveness`, `subscribe_events`), `Wallet`
> (multisig), `KeyPair` (ed25519 sign), `BoxKey` (X25519 NaCl-box `encrypt_to`/
> `open`), and the `Address`/`Pubkey`/`Signature` newtypes — is the recommended
> entry point over this plane. See the README "Using gosh-ackinacki as a library".
>
> The **inference market** rides this plane too (`gosh_ackinacki::inference`,
> lean): `ChainClient::inference_order_book` snapshots ALL open orders of a
> per-model order book from one BOC fetch, and
> `ChainClient::subscribe_inference_events` streams the typed market events
> (placed / cancelled / filled / …). The same `InferenceEvent` decoder plugs
> into Plane B via `AbiRegistry::with_inference_market()` +
> `FilterRule::inference_market_events()`.

> Addressing: the BM (Acki Nacki v3) takes a strict 64-hex `account_id` plus a
> `dapp_id` — never a legacy `0:<hex>`. Contract getters still *return* `0:<hex>`;
> `getter::bare_account_id` strips the `0:` and `getter::resolve_dapp_id` supplies
> the `dapp_id` before any value is fed back to the SDK. See the v3 migration note
> in the README.

## Plane B — your own block-stream indexer via Block Keepers (heavy, opt-in)

If you want to **be your own indexer** — consume the raw block firehose instead
of querying the BM — you connect to the **Block Keeper (BK)** nodes over QUIC:

1. `transport::pool::run(bk_nodes, …)` — a QUIC connection pool (via **MsQuic**)
   to the BK nodes, with failover and hot config reload.
2. `decoder::block` — bincode-deserializes `Envelope<AckiNackiBlock>` (types from
   the `node` crate) and extracts the `tvm_block`.
3. `filter::engine::process_block` — walks account blocks → transactions →
   messages and matches them against a `FilterConfig` (by address / ABI rule).
4. `transform::to_fact` — turns each matched message into a `BlockchainFact`.
5. `MemoryClient::ingest_facts` — pushes the facts into gosh.memory.

This plane requires the `node` and `transport-layer` crates from the **public**
node [`ackinacki/ackinacki`](https://github.com/ackinacki/ackinacki), which pull
**MsQuic** (a cmake ≥ 3.20 / `libnuma` / bundled-`quictls` native build — see the
README Troubleshooting section). It is **only** needed to run your own ingest —
and it builds entirely from **public** repos (no fork, no `[patch]`): the node
plus `tvmlabs/tvm-sdk` on `v3.0.3-rc.an`, a single `tvm_block` across the graph.

## The `block-stream` Cargo feature

The two planes map onto one feature:

| build | feature | pulls | gives you |
|-------|---------|-------|-----------|
| **default (lean)** | `block-stream` **off** | reqwest + TVM SDK | Plane A — thin chain client, multisig, crypto, MCP read/write/payment tools. No node, no MsQuic. |
| **full agent** | `--features block-stream` | + `node`, `transport-layer`, MsQuic | Plane A **and** Plane B — the block-firehose indexer that ingests into gosh.memory. |

What the feature gates: `transport`, `decoder`, `transform`, `BlockCommand`,
`filter::engine::process_block` (+ its helpers and `MatchedMessage`), and
`MemoryClient::ingest_facts`. `filter::engine::AbiRegistry` and everything in
Plane A stay ungated.

A **consumer** (e.g. a thin client that implements its own backend over the chain
primitives) depends on the lean default and never compiles the node:

```toml
[dependencies]
gosh-ackinacki = { git = "https://github.com/gosh-dot-ai/gosh.ackinacki", tag = "gosh-ackinacki-v0.2.0", default-features = false }
```

## Runtime modes (the binary)

The `gosh-ackinacki` binary exposes the same code in three modes (see the README
"Runtime modes"):

- **full agent** (default flags) — needs gosh.memory. Runs Plane B ingestion
  **only when built with `--features block-stream`**; without the feature it
  serves the MCP surface + gosh.memory but does not ingest the BK firehose.
- **`--read-only`** — no gosh.memory; Plane A chain-first reads only.
- **`--stateless-payments`** — no gosh.memory, no keys; Plane A reads plus
  user-signed payment-intent preparation.

`--read-only` and `--stateless-payments` use only Plane A, so the lean default
build is the right one for those deployments.
