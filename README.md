# KeyTruth

Find forgotten API keys.
Check which ones still work.
Detect dangerous reuse.
Nothing leaves your machine.

## Install

```bash
pipx install keytruth
```

---

## 1. Local Scan

Scan your local projects to find credentials without sending anything over the network:

```bash
keytruth scan .
```

This generates a fast, local-only inventory of keys and any placeholders found.

## 2. Probe

Check if the keys actually work by testing them against their provider networks. KeyTruth uses read-only verification endpoints. No plaintext keys are cached.

```bash
keytruth probe
```

The CLI defaults to an actionable dashboard that groups your working keys and flags any invalid or reused credentials.

## 3. Act

When the dashboard highlights an issue (e.g., a reused live key or invalid credentials), drill down to inspect it:

```bash
keytruth show <key-id>
```

This returns precisely where the key is located and provides targeted recommendations to fix it.

## 4. Verify

After rotating or deleting the key, simply run the scan and probe again to verify that the issue has been resolved.

```bash
keytruth scan .
keytruth probe
```
