# Changelog

## 0.1.0 — 2026-08-07

First friend-test release.

- `scan` / `probe` / `show` CLI over local `.env*` files
- Zero runtime dependencies
- Fact-table output, `--json`, `--debug`
- Risk derived at display time: `CRITICAL` only for proven-live reuse; unprobed / dead / `sk_test_` reuse is `REVIEW`
- Cache `~/.api_keys_cache.json` mode `0600`, no plaintext secrets
- Stripe balance opt-in via `--financial`
