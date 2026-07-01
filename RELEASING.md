<!-- Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd. -->
<!-- SPDX-License-Identifier: MIT -->

# Releasing `gosh-ackinacki`

`gosh-ackinacki` is published as a public, MIT-licensed library other apps depend
on. Public releases are **disciplined** — this is enforced by the publish script,
not left to memory.

## Versioning (SemVer, pre-1.0)

The crate is `0.x`. Following Cargo/SemVer for `0.x`:

| Change | Bump | Example |
|--------|------|---------|
| New public API, **or** any breaking change (removed/renamed/retyped item, observable behavior change) | **minor** `0.MINOR.0` | `0.1.0 → 0.2.0` |
| Backward-compatible fix, or a dependency bump with no API change | **patch** `0.x.PATCH` | `0.2.0 → 0.2.1` |

- **`Cargo.toml`'s `version` is the single source of truth.**
- The git tag is always **`gosh-ackinacki-v<that version>`** — bare `vX.Y.Z`
  collides with the upstream node's own tags (not in our `main`), and `sdk-` is a
  module name, not the crate name.
- Never hide a breaking change under a patch bump.

## Every public release MUST

1. **Bump `version` in `Cargo.toml`** per the table above.
2. **Add a `CHANGELOG.md` entry** `## [<version>] - <YYYY-MM-DD>` listing
   Added / Changed / Removed / Fixed, marking any **BREAKING** change.
3. Pass the gates — both lean and `--features block-stream`:
   `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`;
   plus the live shellnet E2E when the money/chain path changed.
4. Publish via **`scripts/publish-public-mirror.sh`**.

## What the publish script enforces

`scripts/publish-public-mirror.sh` is the only gate for a public release. Before
it pushes, it **refuses** unless:

- `CHANGELOG.md` has a `## [<version>]` section for the current `Cargo.toml`
  version, and
- that version is **not already tagged** on the public mirror (so you cannot
  re-publish without bumping).

On success it **auto-creates** the `gosh-ackinacki-v<version>` tag on **both** the
private source (`origin`) and the public mirror. So: bump + changelog → publish →
the tag follows automatically and always matches `Cargo.toml`.

## Do not

- Re-publish without bumping the version (the script refuses).
- Force-move an already-published tag (breaks reproducibility for anyone pinned).
