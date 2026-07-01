<!-- Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd. -->
<!-- SPDX-License-Identifier: MIT -->

# Changelog

All notable changes to `gosh-ackinacki` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/); the project follows SemVer
(pre-1.0: a `0.MINOR.0` bump may break the API, a `0.x.PATCH` bump is
backward-compatible). Release process: see [RELEASING.md](RELEASING.md).

## [0.3.1] - 2026-07-01

### Fixed
- **`private-note` fail-fast on the wrong funding-wallet type** (dexdo-specs#196).
  `deploy_private_note_from_multisig` forwards `RootPN.generateVoucher` through the
  6-arg `UpdateCustodianMultisigWallet` `sendTransaction`. A generic Multisig has a
  7-arg `sendTransaction(...,dapp_id)` with a different function selector, so it
  silently dropped the voucher message → no `VoucherGenerated` → an opaque ~480s
  timeout. The mint now checks the funding wallet's on-chain `code_hash` up front
  and returns an explicit error (naming the actual hash, the required
  `UpdateCustodianMultisigWallet` hash `8470e1da…`, and the generic-Multisig case)
  before sending anything. Verified live on shellnet: fails in ~2s, not 480s.

## [0.3.0] - 2026-06-30

### Added
- **`private-note` feature** (optional, off by default) — in-process DEX
  PrivateNote minting (`private_note::deploy_private_note_from_multisig`): the
  wallet-funded `RootPN.generateVoucher` → `deployPrivateNote` →
  `sendEccShellToPrivateNote` path with a halo2 voucher prover, ported from
  `gosh-sh/dexdo` so consumers neither shell out to `onboard_user_shellnet` nor
  pull a second TVM SDK. Builds entirely from PUBLIC repos (`dexdo-halo2-kit`,
  `halo2-lib-…`). The lean default build never compiles the heavy proving graph.

### Security
- The voucher secret `sk_u` is now sampled from the **OS CSPRNG** (was derived
  from PID + wall-clock via SHA-256 — low-entropy and brute-forceable, which
  would have defeated the voucher's privacy). `skUCommit = poseidon([sk_u, 0])`.

### Fixed
- The `private-note` live paths (`mint_voucher_via_multisig`,
  `prove_voucher_for_event`) now return `Err` instead of `.expect()`/`panic!` on
  network / proof / encoding failures — a transient error no longer crashes a
  host embedding the library in-process. `hex_u256_to_dec` is fallible.

## [0.2.0] - 2026-06-25

### Added
- `sdk::BoxKey` — authenticated X25519 sealing (NaCl `crypto_box` over
  `tvm_client::crypto`): `generate` / `from_secret_hex` / `encrypt_to` / `open`,
  plus `SealedMessage`. Self-contained, no dependency on gosh.memory.
- AI Registry review hardening (issue #15): `read_events` fails **closed** on a
  missing GraphQL account/messages node (`parse_messages_page` + tests);
  `airegistry_set_manifest` schema now requires the package body (`anyOf`); the
  MCP server token is written with an atomic `0600` temp-file+rename.

### Changed
- **tvm-sdk bumped `v3.0.2.an` → `v3.0.3-rc.an`** (Windows build fix #270 +
  additive executor-params #235). The whole stack — `gosh-ackinacki`, the public
  node `ackinacki/ackinacki`, and `tvmlabs/tvm-sdk` — unifies on a single
  `tvm_block`, with no `[patch]` and no fork.
- **block-stream indexer now depends on the PUBLIC node `ackinacki/ackinacki`**
  (was the private `gosh-sh/acki-nacki`), so the indexer builds entirely from
  public repositories.
- **BREAKING:** `sdk::KeyPair` no longer derives `Clone` and stores its secret in
  a zeroizing buffer (was a plain `String`). Pass it by reference. (Security
  hardening — issue #15 finding 6.)
- `wallet::query::send_message` now surfaces a Block Manager refusal
  (`QUEUE_OVERFLOW` / synchronous `TVM_ERROR`) as `Err` instead of swallowing it.

### Removed
- `daily_limit` from the public `set_wallet_policy` schema — it was advertised
  but never enforced (a fail-open shape). The struct field remains, documented as
  advisory-only.

### Fixed
- Docs: `package_sha256` clarified as off-chain pointer/cache metadata, **not**
  on-chain TokenContract state; verify package integrity via
  `airegistry_get_manifest`.

## [0.1.0] - 2026-06-22

### Added
- First library facade `gosh_ackinacki::sdk`: `ChainClient`
  (connect / get_account + balances / run_getter / call / deploy /
  chain_liveness / subscribe_events), `Wallet` (multisig submit/confirm),
  `KeyPair` (ed25519 sign/verify), and the `Address` / `Pubkey` / `Signature`
  newtypes, plus a runnable `examples/sdk_lean_client.rs`.
- `block-stream` Cargo feature-gate — the lean (Plane A) build is the default;
  the QUIC firehose indexer (Plane B) is opt-in. `node` / `transport-layer`
  become optional dependencies.
- Chain-halt detection: `AccountReader::chain_liveness` (block-production probe)
  + `QUEUE_OVERFLOW` surfacing in `send_message`.
- `docs/ARCHITECTURE.md` (the two data planes, the indexer pipeline, the build
  matrix) and the public MIT mirror at `gosh-dot-ai/gosh.ackinacki`.
