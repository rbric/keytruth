# KeyTruth

Find forgotten API keys.
Check which ones still work.
Detect dangerous reuse.
Nothing leaves your machine.

```bash
python3 keytruth.py scan .
python3 keytruth.py probe --yes
python3 keytruth.py show <key-id>
```

Or: `pipx install keytruth`

## Output

Default is a fact table. No dashboard.

```
keytruth 0.1.0  probe  files=-  creds=3/3  providers=2  critical=1  invalid=0
PROVIDER     KEY      AUTH       ACCESS       RISK     FILES  METRIC
------------------------------------------------------------------------
STRIPE       bbbbbbbb Detected   Not probed   CRITICAL     2  Live key — opt-in required
OPENAI       abcdef12 Valid      Working      NONE         1  Balance $12.40
```

Flags that matter:

- `--json` — machine output
- `--debug` — print the wire (URL, status, body slice, classification)
- `--reused` — only multi-file credentials
- `--placeholders` — include empty/placeholder values
- `--financial` — opt-in Stripe balance probe
- `--yes` — skip first-probe trust prompt

## Rules

1. `scan` never hits the network.
2. Cache is `~/.api_keys_cache.json` mode `0600`. No plaintext keys.
3. Same candidate key in >1 file → `CRITICAL`. Placeholders don't count.
4. Stripe live balance requires `--financial`.

## Flow

```bash
keytruth scan ~
keytruth probe --yes
keytruth show a1b2c3d4
# rotate / delete
keytruth scan ~
keytruth probe --yes
```
