# Security

KeyTruth is a **local** credential tool. It does not upload secrets to a KeyTruth server (there isn’t one).

## What leaves your machine

- **`scan`**: nothing. Reads `.env*` files on disk only.
- **`probe`**: each candidate key is sent **directly to that provider** (OpenAI, Anthropic, Stripe, …) using their normal HTTPS APIs, on read-only or free verification endpoints where possible.
- First `probe` asks for confirmation unless you pass `--yes`.
- Stripe **balance** queries require `--financial`. Live keys are detected without that flag but not balance-probed.

## What is stored

- Cache path: `~/.api_keys_cache.json`
- Permissions: `0600`
- Stores hashes, masked previews, file paths, and probe classifications
- **Does not** store plaintext secret values
- Stripe financial amounts are not persisted in the cache

## Trust boundary

Treat `probe` like pasting a key into the provider’s own API. If you do not want a provider to see a key, do not probe it (remove it before probe, or avoid scanning that tree).

## Reporting issues

Open a GitHub issue on the repository, or contact the maintainer privately for sensitive reports. Do not paste live secrets into issues.
