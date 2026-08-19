<!-- Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd. -->
<!-- SPDX-License-Identifier: MIT -->

# Changelog

All notable changes to `gosh-ackinacki` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/); the project follows SemVer
(pre-1.0: a `0.MINOR.0` bump may break the API, a `0.x.PATCH` bump is
backward-compatible). Release process: see [RELEASING.md](RELEASING.md).

## [0.10.0] - 2026-08-19

Keeps the crate in step with what the dexdo CLI actually runs against live shellnet.
**Every previously supported wallet keeps working** — this release only adds the newer
one and refreshes upstream artifacts.

### Added
- **`MultisigKind::UpdateCustodianV2_4`** — `UpdateCustodianMultisigWallet_v2`
  **v2.4.0** (`cfcaac10d43c8dc0…`), the CURRENT canonical funding wallet, vendored from
  `gosh-sh/acki-nacki` `contracts/0.81.0_compiled/…` (commit `44fe02ea`; sha256 recorded
  in `contracts/msig/PROVENANCE.md`). It is both deployable via `deploy_multisig` and
  accepted by the private-note funding-forward path.
  - **Its constructor differs**: v2.4.0 additionally takes `minBalance` + `targetBalance`
    (`uint128`). Constructor arguments are therefore built **per version**
    (`"0"`/`"0"`, matching the canonical operational wallet), and a new test asserts the
    built arguments equal each vendored ABI's declared constructor — so a future wallet
    whose constructor changes again fails loudly instead of mis-deploying.
  - The call shape is unchanged from v2.2.0 (7-arg `submitTransaction` carrying the
    RootPN `dapp_id`).
- **v2.2.0 (`09f596d5…`) remains fully supported** — it is dexdo's
  `LEGACY_SPENDING_CODE_HASH`. Existing wallets keep funding notes; only new deploys
  should pick `UpdateCustodianV2_4`.

### Changed
- **BREAKING (only for exhaustive `match`):** `MultisigKind` gains a variant. Callers
  that match it exhaustively must add an arm; every other use is source-compatible.
- **`tvm-sdk` pinned to `v3.0.4-rc.an`** (was `v3.0.3-rc.an`) — the same revision
  (`88d50d38`) the dexdo CLI already forces via a `[patch]` block for `ExtOutMsgInfoV2`
  action support and the Windows-invalid-path fix. Consumers on v3.0.4 can now drop that
  patch. No source changes were needed.

### Fixed
- **PrivateNote getters work again** — `run_tvm` on the pinned v3.0.3 SDK could not parse
  the return action of *any* PrivateNote getter ("TVM internal error: can not parse
  actions"), which is why `deploy_private_note_from_multisig` had to report
  `sanity_checked: false` and why a caller whose flow requires `getDetails` could not
  finalize a note. The v3.0.4 pin fixes the parse: live-verified against a freshly minted
  note on shellnet 4.0.35 — `getDetails`, `getVersion`, `_depositIdentifierHash` and
  `getPMPCode` all return, and a full mint now reports **`sanity_checked: true`**. The
  getter remains best-effort in the deploy (the authoritative acceptance is still the
  on-chain PN Active + ECC[2] effect), so a future SDK/compiler regression degrades
  rather than fails the deploy.
- **`PrivateNote.abi.json` refreshed** from upstream `gosh-sh/acki-nacki`
  `contracts/0.81.0_compiled/dex/` — adds `claimInferenceForfeit`, updates the
  constructor (`tokenContractCode*`, `rootModelCode*`) and the `postSellOffer` /
  `stream*` signatures. None of the changed entrypoints are called by this crate, and
  every entrypoint it does call is unchanged. `RootPN.abi.json` was already identical to
  upstream and is untouched. Provenance recorded in `contracts/dex/PROVENANCE.md`
  (dexdo's private deal-model DEX fork is deliberately not tracked).

## [0.9.2] - 2026-08-06

### Fixed
- **PrivateNote minting is now explicitly SERIAL.** `deploy_private_note_from_multisig`
  takes a process-wide latch before any wallet spend and **fails fast** if another
  deploy is already in flight. Concurrent mints were unsafe — the halo2 prover
  writes a shared on-disk cache (`pk_cache.bin` / `break_points_cache.bin` /
  `vk_cache.bin` at fixed names under `prover_cache_dir`) and the funding wallet
  mints one voucher at a time, so two deploys at once would corrupt the cache and
  race the wallet. The latch is released on drop (including on error/panic), so a
  failed mint never leaves it stuck. Serial callers are unaffected; a parallel call
  now returns a clear "note minting must be SERIAL" error instead of silently
  racing. (In-process guard; a single `prover_cache_dir` must still not be shared
  across concurrent processes.)

## [0.9.1] - 2026-08-06

### Fixed
- **`private-note` note-deploy now works on shellnet 4.0.33.** The network migrated
  the RootPN premine into DApp **`"4"`** (was `"0"`) and recompiled it (new
  `code_hash`), so a v1 funding wallet's `sendTransaction` no longer routed the
  internal `generateVoucher` to RootPN — `deploy_private_note_from_multisig` hung
  waiting for a `VoucherGenerated` that never came. Adopts the recipe the dexdo CLI
  proves live on 4.0.33 (its funding wallet + our prover/RootPN ABI, unchanged):
  - the funding-forward path now issues the wallet call **per version** — the
    canonical **v2** wallet forwards via **`submitTransaction`** carrying the RootPN
    `dapp_id` (`"4"`), which routes `generateVoucher` to the migrated RootPN; v1
    (6-arg `sendTransaction`) and the generic Multisig (7-arg) are unchanged;
  - the **deposit** voucher now attaches **`nominal + GAS_DEPOSIT`** (250 SHELL,
    `contracts/dex/modifiers/modifiers.sol`); RootPN deducts `GAS_DEPOSIT` and emits
    the nominal, which the proof and `deployPrivateNote.value` continue to use. The
    fee/gas leg is unchanged. `RootPN.deployPrivateNote` / getters keep
    auto-resolving the RootPN's DApp, so no explicit routing change was needed there.
  - Live-confirmed end to end on shellnet 4.0.33 (RootPN `7de9af53…`): a fresh v2
    wallet deployed via `deploy_multisig`, then a full mint — PN Active + ECC[2]
    SHELL funded, no 137/403 (our pinned halo2 kit stays compatible with the new
    verifier).

## [0.9.0] - 2026-08-05

### Added
- **Public multisig-wallet deployment** (gosh-dot-ai/gosh.ackinacki#5). A consumer
  (e.g. the dexdo CLI) can now deploy a funding wallet through the crate instead of
  shipping its own mechanism. New at the crate root: `deploy_multisig`,
  `DeployMultisigParams`, `MultisigKind`, `FundingSource`.
  - **A single wallet-version registry** (`wallet::multisig::MultisigKind`) is the
    one source of truth for every multisig the crate understands, keyed by on-chain
    `code_hash`: `UpdateCustodianV1` (`8470e1da`), `UpdateCustodianV2` (`09f596d5`,
    the canonical dexdo funding wallet from `gosh-sh/ackinacki-kit` v5.0.0), and the
    forward-only generic Multisig (`3a7a5324`). Each entry carries its ABI, deploy
    TVC, and `sendTransaction` shape (v1 is 6-arg; v2 and generic are 7-arg with a
    trailing `dapp_id`). Adding a future version is one variant + its vendored
    artifacts.
  - `deploy_multisig` takes the wallet version **explicitly** (no default),
    constructs the wallet with `owner_pubkeys` (default `[deployer]`) and
    `req_confirms`, and verifies the deployed `code_hash` equals the requested
    version. It **fails closed**: a forward-only kind is rejected up front, and
    `FundingSource` is explicit — `Giver` (testnet) funds the deterministic deploy
    address before the StateInit, while `Prefunded` (mainnet) assumes the caller
    funded it and surfaces an activation-timeout error rather than half-deploying.
  - Live-confirmed on shellnet: a v2 wallet deploys to Active with code hash
    `09f596d5…`, with the deployer key as custodian and `reqConfirms = 1`.

### Changed
- **`private-note`:** the funding-forward path
  (`halo2::multisig_voucher::mint_voucher_via_multisig`) now resolves the caller's
  funding wallet through the shared `wallet::multisig` registry, so it **also
  accepts `UpdateCustodianMultisigWallet_v2` (`09f596d5`)** in addition to v1 and
  the generic Multisig. Behaviour for the previously supported wallets is
  unchanged (v1 6-arg, generic 7-arg with caller-supplied `dapp_id`).

## [0.8.0] - 2026-07-23

### Fixed
- **`private-note` note-deploy now works and no longer silently fails with RootPN
  403 `ERR_INVALID_HISTORY_PROOF`** (gosh-dot-ai#4; public cluster dexdo-cli
  #66/#68/#76/#77; dexdo-cli-private #483/#505). Two independent problems:
  1. **The pinned halo2 kit rev produced a circuit `gosh.zkhalo2verify` rejects.**
     `main` had drifted the `dexdo-halo2-kit` pin to `e7944e9`, whose proof the
     on-chain verifier aborts with **exit 137**. Re-pinned to `89e9346` — the exact
     rev the live-proven `gosh-ackinacki-v0.4.1` release ships and that
     `dexdo-cli-private` deploys notes with — plus the stable-Rust `[patch]` graph
     so it still builds off nightly. A full mint is now **live-confirmed** on
     shellnet (PN Active + ECC[2] SHELL funded).
  2. **A stale layer-0 history proof aborted 403, and the abort was swallowed.**
     The halo2 proof races the tight layer-0 (`W=128` blocks, ~2 min) window; a
     slow CPU-bound prover lets the historical root age out, so
     `deployPrivateNote` / `sendEccShellToPrivateNote` abort **403**. The async
     `/v2/messages` submit returns `Ok` on *queue* and `send_message` only checked
     top-level Block-Manager errors, not the compute `exit_code`, so a note could be
     left `shell_funded: true` with zero ECC. `deploy_private_note_from_multisig`
     now surfaces and classifies the abort honestly:
     - **`check_bm_error` reads the compute `exit_code` from both response shapes**
       — a top-level `error` object *and* the `/result/{exit_code,aborted}` an
       executed `/v2/messages` returns — so `{ "result": { "exit_code": 403,
       "aborted": true } }` is no longer returned as `Ok`. A queue-only ack stays
       `Ok`.
     - **403 and 137 are classified distinctly.** **403 `ERR_INVALID_HISTORY_PROOF`**
       (aged-out history root) fails closed naming the already-paid operation (its
       depositIdentifierHash / PrivateNote address) and directing the operator to
       verify/recover manually — **never to blindly re-run** (a re-run mints another
       paid voucher). **137 `ERR_INVALID_ZKPROOF`** (the proof does not verify — a
       circuit/kit mismatch, exactly what the bad `e7944e9` pin produced) is **not**
       described as stale history and **not** retryable; it fails closed pointing at
       the kit pin. Every other code passes through on its real value.
     - **No automatic wider-layer / fail-recovery machinery.** At `W=128` the next
       history layer is ~16384 blocks (hours) away, so an automatic same-voucher
       fallback would hang or double-mint. On a stale-proof abort the deploy fails
       closed and names the paid operation; **the operator verifies/recovers
       manually** rather than blindly re-running. **The automatic 403 self-heal that
       issue #4 asks for is therefore intentionally not implemented; #4 stays open.**
       This change delivers the working note-deploy (kit pin) and honest abort/effect
       handling.
     - **Requires the on-chain ECC[2] effect before reporting success** — after
       `sendEccShellToPrivateNote` it polls the PrivateNote's **ECC[2] SHELL**
       balance and distinguishes a **confirmed** shortfall from a **read outage**
       (an unobserved balance is reported as UNKNOWN, never as a confirmed missing
       effect). A note is never reported funded without the SHELL actually on-chain.
     - The post-deploy `PrivateNote.getDetails` sanity getter is **best-effort**
       (the pinned tvm-sdk `run_tvm` cannot parse *any* PrivateNote getter's return
       action under the current `sold` — "can not parse actions"); a getter quirk no
       longer fails an otherwise-complete, effect-verified deploy.

### Changed
- **`private-note`:** the deploy verifies the on-chain **ECC[2] SHELL** effect
  before returning success (previously `shell_funded: true` was assumed once the
  call was accepted). No public API shape changed.

## [0.7.0] - 2026-07-02

### Added
- `sdk::ChainClient::call_in_dapp` — a signed external call **routed to an
  explicit DApp** (instead of assuming `dapp == address`). This is the generic
  transport service a consumer uses to write to an account that lives in a DApp
  other than its own id — e.g. a DEX PrivateNote (deployed inside a
  system/registry DApp). The caller supplies the ABI / method / args (its own
  contract logic); this crate embeds no DApp id and no DEX write flow. It is a
  *service* for building on Acki Nacki, not a duplicate of the app's write path.

### Notes
- The DEX system DApp id (`inference::book::SYSTEM_DAPP_ID`, currently `0`) is a
  **network-config value** — a scheduled update moves notes/books to id `4`.
  Every read/write helper already takes the DApp explicitly, so consumers pass
  the new id with no code change here; the constant is documented as today's
  default only.

## [0.6.0] - 2026-07-02

### Added
- **Inference-market read side** — new **lean** `inference` module (no halo2 /
  `private-note` feature needed):
  - `inference::fetch_order_book` / `sdk::ChainClient::inference_order_book` —
    a consistent snapshot of **all open orders** of a per-model
    `InferenceOrderBook` (bids/asks in price-time order, best bid/ask, stats,
    model identity), reconstructed from ONE BOC fetch with local getters. Auto
    DApp resolution (own id, then the system DApp for note-deployed books).
  - `inference::InferenceEvent` — **typed market events** (order placed /
    cancelled / **filled** with clearing price, executed, refunded,
    subscriptions, book deployed) plus note-side confirmations and RootPN note
    lifecycle; lossless u256 prices; serde-serializable.
  - `sdk::ChainClient::subscribe_inference_events` — an async `Stream` of typed
    market events for an order book (whole market of one model) or a
    PrivateNote (one trader's activity).
  - embedded `InferenceOrderBook.abi.json` (`inference::abi`).
- **Block-stream filter: market-wide decoding.** `filter::engine::AbiRegistry`
  gains **global ABIs** (`register_global`, `with_inference_market`) matched by
  contract *type* — order books / notes deploy at unknown addresses, so events
  now decode without pre-registering each address. New `FilterRule` presets:
  `inference_market_events()` (the full market feed) and
  `private_note_events()` (notes only).
- `airegistry::getter`: generic event plumbing — `EventPage<E>` /
  `EventRecord<E>` (default `AiRegistryEvent`, existing callers unchanged),
  `read_events_with` / `parse_messages_page_with` for caller-supplied decoders.

## [0.5.0] - 2026-07-01

### Changed
- **BREAKING (`private-note`):** the library no longer hardcodes a specific DEX
  deployment. `deploy_private_note_from_multisig` mints against a **caller-supplied
  RootPN**: `DeployPrivateNoteParams` gains two required fields —
  `root_pn_address: Address` and `forward_dapp_id: String` — and the
  `artifacts::ROOT_PN_ADDRESS` constant (`0:1010…1010`) plus the internal
  `ROOT_PN_DAPP_ID` (`"0"`) are **removed**. A generic Acki Nacki agent library
  should not embed a particular DEX system contract's address / DApp routing.
  See **[MIGRATING.md](MIGRATING.md)** for the exact before/after and the values
  that reproduce the previous shellnet behavior. The embedded RootPN/PrivateNote
  ABIs, wallet-type detection, and fail-fast are unchanged.

## [0.4.0] - 2026-07-01

### Added
- **`private-note` now supports the generic ackinacki-kit `Multisig` funding
  wallet** (dexdo-specs#196), the type users/dashboards are actually issued. The
  voucher forward branches on the funding wallet's on-chain `code_hash`:
  the generic Multisig (`3a7a5324…`) gets a 7-arg
  `sendTransaction(dest,value,cc,bounce,flags,payload,dapp_id=0)`, the historical
  `UpdateCustodianMultisigWallet` (`8470e1da…`) keeps the 6-arg form, and any
  other type still fails fast with an explicit error. Integrated from the
  live-validated public PR #3 (`generic-multisig-voucher`) on top of the 0.3.x
  hardening. Supersedes the 0.3.1 fail-fast-only guard.

### Changed
- The wallet-type check moved from a pre-mint guard (0.3.1, onboard) into the
  voucher forward itself (`MultisigForwardKind::from_code_hash`), so a supported
  wallet is now *served* rather than merely rejected.

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
