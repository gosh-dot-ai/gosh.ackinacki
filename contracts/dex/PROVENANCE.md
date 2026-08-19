# Vendored DEX contract ABIs

Source of truth: **gosh-sh/acki-nacki** (branch `dev`) — the upstream contracts, NOT
dexdo's private fork. dexdo compiles its own DEX branch (deal-model entrypoints such as
`creditFromDeal` / `fundDeal` / `onDealClosed` / `sweepShell`, and `RootPN.reportDealWriteOff`);
those are deliberately NOT tracked here.

| file | upstream path | notes |
|---|---|---|
| `RootPN.abi.json` | `contracts/0.80.0_compiled/dex/RootPN.abi.json` | byte-identical to upstream `dev` |
| `PrivateNote.abi.json` | `contracts/0.81.0_compiled/dex/PrivateNote.abi.json` | refreshed 2026-08 |

Note: the TVCs published upstream do not match the code hashes actually deployed on
shellnet (the network runs its own build), so the ABI — not the TVC — is the contract
this crate binds to. The functions this crate calls (`generateVoucher`,
`deployPrivateNote`, `sendEccShellToPrivateNote`, `getPrivateNoteAddress`,
`deployInferenceOrderBook`, `placeInferenceBuy`, order-book getters) are identical across
upstream and dexdo, which is why live minting works against the deployed RootPN.
