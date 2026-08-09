---
name: hyperliquid
description: Hyperliquid market data, account history, trade review.
version: 0.1.0
author: Hugo Sequier (Hugo-SEQUIER), Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [Hyperliquid, Blockchain, Crypto, Trading, Perpetuals, Spot, DeFi]
    related_skills: []
---

# Hyperliquid Skill

Query Hyperliquid market and account data through the public `/info` endpoint.
Read-only — no API key, no signing, no order placement.

13 commands: `dexs`, `markets`, `spots`, `candles`, `funding`,
`funding-contract`, `l2`, `state`, `spot-balances`, `fills`, `orders`, `review`,
`export`. Stdlib only
(`urllib`, `json`, `argparse`).

---

## When to Use

- User asks for Hyperliquid perp or spot market data, candles, funding, or L2 book
- User wants to inspect a wallet's perp positions, spot balances, fills, or orders
- User wants a post-trade review combining recent fills with market context
- User wants to inspect builder-deployed perp dexs or HIP-3 markets
- User wants a normalized JSON export of candles + funding for backtesting prep

---

## Prerequisites

Stdlib only — no external packages, no API key.

The script reads `${HERMES_HOME:-~/.hermes}/.env` for two optional defaults:

- `HYPERLIQUID_API_URL` — defaults to `https://api.hyperliquid.xyz`. Set to
  `https://api.hyperliquid-testnet.xyz` for testnet.
- `HYPERLIQUID_USER_ADDRESS` — default address for `state`, `spot-balances`,
  `fills`, `orders`, and `review`. If unset, pass the address as the first
  positional argument.

A project `.env` in the current working directory is honored as a dev fallback.

Helper script: `~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py`

---

## How to Run

Invoke through the `terminal` tool:

```bash
python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py <command> [args]
```

Add `--json` to any command for machine-readable output.

---

## Quick Reference

```bash
hyperliquid_client.py dexs
hyperliquid_client.py markets [--dex DEX] [--limit N] [--sort volume|oi|funding_abs|change_abs|name]
hyperliquid_client.py spots [--limit N]
hyperliquid_client.py candles <coin> [--interval 1h] [--hours 24] [--limit N]
hyperliquid_client.py funding <coin> [--hours 72] [--limit N]
hyperliquid_client.py funding-contract <coin> --start-time-ms N --end-time-ms N --output-dir PATH --authorization-receipt PATH
hyperliquid_client.py l2 <coin> [--levels N]
hyperliquid_client.py state [address] [--dex DEX]
hyperliquid_client.py spot-balances [address] [--limit N]
hyperliquid_client.py fills [address] [--hours N] [--limit N] [--aggregate-by-time]
hyperliquid_client.py orders [address] [--limit N]
hyperliquid_client.py review [address] [--coin COIN] [--hours N] [--fills N]
hyperliquid_client.py export <coin> [--interval 1h] [--hours N] [--output PATH]
```

For `state`, `spot-balances`, `fills`, `orders`, and `review`, the address is
optional when `HYPERLIQUID_USER_ADDRESS` is set in `${HERMES_HOME:-~/.hermes}/.env`.

---

## Procedure

### 1. Discover DEXs and Markets

```bash
python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py dexs

python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  markets --limit 15 --sort volume

python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  spots --limit 15
```

- `--dex` only applies to perp endpoints; omit for the first perp dex.
- Spot pairs may show as `PURR/USDC` or aliases like `@107`.
- HIP-3 markets prefix the coin with the dex, e.g. `mydex:BTC`.

### 2. Pull Historical Market Data

```bash
python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  candles BTC --interval 1h --hours 72 --limit 48

python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  funding BTC --hours 168 --limit 30
```

Time-range endpoints paginate. For larger windows, repeat with a later
`startTime` or use `export` (below).

`funding-contract` is a control-only path for an exact, owner-preregistered
funding request. It is disabled unless a separate authorization receipt and its
SHA-256 are supplied through
`HERMES_FUNDING_CONTRACT_AUTHORIZATION_SHA256`. The receipt binds the command,
source files, endpoint, request, output namespace, and one-shot consumption
marker. The authorization is consumed before the single HTTP request; failures
do not retry or restore it. Raw response bytes are durably published before
parsing. Its receipt never claims completeness, causal research readiness,
strategy authority, or trading authority.

`scripts/candle_raw_capture_adapter.py` is the separate BTC-only raw candle
path. It requires an exact-hash owner run-intent, denies credential-bearing
environment variables before opening a socket, performs one `candleSnapshot`
request with zero retries and redirects, durably stores request/response bytes,
and records only candles whose `T` is earlier than the local request-start
wall clock. Its receipt keeps source availability, native sequencing,
completeness, realtime, causal, strategy, and trading claims unknown or false;
it never calls `hyperliquid_client.py`.

`funding_pagination_controller.py` is an offline-only bounded pagination
controller. It consumes immutable receipts, verifies exact receipt-file,
request, raw, and source bindings through single `O_NOFOLLOW` regular-file
reads, and emits a review-required next-page intent with
`network_fetch=false`; it never creates an authorization or opens a socket.
The cursor is the predecessor maximum event time (not `last_time + 1`) so
boundary rows are intentionally overlapped. Page numbers and cumulative
page/row/byte limits come only from an exact-SHA intent lineage anchored at
page 1; caller-supplied page numbers and path-only assembly are rejected. Raw
pages are never merged or deduplicated. A later aggregate contains only page
hashes, row counts, byte counts, and time bounds; boundary row-set identity
ambiguity, empty pages, limits, cycles, and no-progress stop fail closed while
completeness remains `UNKNOWN/REVIEW_REQUIRED`. Receipts missing v2
boundary/code hashes remain `LEGACY_RECEIPT_CODE_HASHES_NOT_RECORDED_REVIEW_REQUIRED`
and cannot be promoted to downstream structural readiness.

`build_legacy_root_bridge()` is an offline-only legacy bridge producer. It
builds a deterministic, append-only canonical JSON bridge for an immutable
first-page receipt but does not publish an artifact unless an explicit caller
uses `write_legacy_root_bridge()` in a separate namespace. The bridge includes
the exact receipt file bytes as base64 plus external file SHA binding, exact
request/raw/source bindings, current code and algorithm versions, and an
explicit `UNKNOWN_LEGACY` acquisition-code provenance state. Its only allowed
use is to validate a page-1 lineage root for a next-page intent; it proves no
acquisition, completeness, semantics, readiness, or authority, and the next
page still requires a separately issued owner authorization. Modern receipts
cannot use a legacy bridge.

### 3. Inspect Live Order Book

```bash
python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  l2 BTC --levels 10
```

Use when asked about book depth, near-term liquidity, or potential market
impact of a large order.

### 4. Review an Account

```bash
python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  state 0xabc...

python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  spot-balances
```

`state` returns perp positions; `spot-balances` returns spot inventory.
Use these for "how are my positions?", "what am I holding?", "how much is
withdrawable?".

### 5. Review Fills and Orders

```bash
python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  fills 0xabc... --hours 72 --limit 25

python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  orders --limit 25
```

### 6. Generate a Trade Review

```bash
python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  review 0xabc... --hours 72 --fills 50

python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  review --coin BTC --hours 168
```

Reports realized PnL, fees, win/loss counts, coin breakdowns, market trend
and average funding for each traded perp, plus heuristics (fee drag,
concentration, counter-trend losses).

For deeper post-trade analysis: start with `review` to find problem coins
or windows → pull `fills` and `orders` for that period → pull `candles`
and `funding` for each traded coin → judge decision quality separately
from outcome quality.

### 7. Export a Reusable Dataset

```bash
python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  export BTC --interval 1h --hours 168 --output ./btc-1h-7d.json

python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  export BTC --interval 15m --hours 72 --end-time-ms 1760000000000
```

Output JSON contains: schema version, source metadata, exact time window,
normalized candle rows, normalized funding rows, summary stats. Use
`--end-time-ms` for reproducible windows.

---

## Pitfalls

- Public info endpoints are rate-limited. Large historical queries may
  return capped windows; iterate with later `startTime` values.
- `fills --hours ...` uses `userFillsByTime`, which only exposes a
  recent rolling window — not full archive history.
- `historicalOrders` returns recent orders only; not a full export.
- The `review` command is heuristic. It cannot reconstruct intent,
  order placement quality, or true slippage from fills alone.
- The `export` command writes a normalized dataset, not a backtest
  engine. You still need your own slippage/fill model.
- Spot aliases like `@107` are valid identifiers even when the UI shows
  a friendlier name.
- `l2` is a point-in-time snapshot, not a time series.

---

## Verification

```bash
python3 ~/.hermes/skills/blockchain/hyperliquid/scripts/hyperliquid_client.py \
  markets --limit 5
```

Should print the top Hyperliquid perp markets by 24h notional volume.
