# KeyTruth

Find forgotten API keys.
Check which ones still work.
Detect dangerous reuse.
Nothing leaves your machine.

**v0.1.0** — local `.env*` credential truth CLI. Not a cloud scanner.

## Install

From this repo (friend-test / local):

```bash
pipx install .
# or without pipx:
pip install .
```

From GitHub (after push):

```bash
pipx install git+https://github.com/rbric/keytruth.git
```

From a local checkout:

```bash
pipx install /path/to/keys-cli
```

Requires Python 3.10+.

Run without installing:

```bash
python3 keytruth.py scan .
python3 keytruth.py probe --yes
python3 keytruth.py show <key-id>
```

## Flow

```bash
keytruth scan ~
keytruth probe --yes
keytruth show a1b2c3d4
# rotate / delete
keytruth scan ~
keytruth probe --yes
```

1. **scan** — local only, no network  
2. **probe** — sends each key to its provider’s read-only / free check endpoints (first run asks for confirmation; use `--yes` to skip)  
3. **show** — paths + one recommended action  

## Output

Fact table. No dashboard.

```
keytruth 0.1.0  probe · 2 files · 2 keys · 0 skipped · 1 critical · 0 review · 0 invalid
PROVIDER     KEY      AUTH       ACCESS       RISK     FILES  METRIC
------------------------------------------------------------------------
STRIPE       bbbbbbbb Detected   Not probed   CRITICAL     2  Live key — opt-in required
OPENAI       abcdef12 Valid      Working      NONE         1  Balance $12.40
```

`scan` prints provider / key / risk / files only.

Useful flags:

| Flag | Meaning |
|------|---------|
| `--json` | Machine output |
| `--debug` | Wire dump (URL, status, body slice) |
| `--reused` | Only multi-file credentials |
| `--placeholders` | Include empty / placeholder values |
| `--financial` | Opt-in Stripe balance probe |
| `--yes` | Skip first-probe trust prompt |

## Rules

1. `scan` never hits the network.
2. Cache is `~/.api_keys_cache.json` mode `0600`. No plaintext keys.
3. Risk is recomputed from files (cached `status.risk` is not trusted).
4. `CRITICAL` only after probe proves the key is live **and** it appears in >1 non-backup file.
5. Scan-time reuse (including `.env.example`) is `REVIEW` until probe; if Valid later → `CRITICAL`.
6. Reused `sk_test_` or dead (Invalid) keys stay `REVIEW`. `.env.backup` / `.bak` don't count.
7. Stripe live balance requires `--financial`.
8. Working keys with no billing endpoint show metric `-`.
9. Scope is `.env*` files for now.

## Privacy / safety

See [SECURITY.md](SECURITY.md).

## Dev

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

MIT
