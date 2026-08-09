#!/usr/bin/env python3
"""Bounded clock-triggered BTC 15m raw collector for Hermes ``no_agent`` cron.

The collector consumes a finite owner contract.  Each authorized slot creates
one exact run intent and invokes the existing one-shot raw adapter once.  It
does not project observations, run a strategy, or create trading authority.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any, Callable, Mapping


CONTRACT_SCHEMA = "hermes.hyperliquid.candle-clock-bound-collector-contract.v1"
CONTRACT_STATUS = "OWNER_APPROVED_BOUNDED_PUBLIC_RAW_COLLECTION_ONLY"
RUN_INTENT_SCHEMA = "hermes.hyperliquid.candle-raw-capture-run-intent.v1"
ENDPOINT = "https://api.hyperliquid.xyz/info"
COMMAND = "candle-raw-capture"
PERIOD_MS = 15 * 60 * 1000
MAX_CONTRACT_BYTES = 256 * 1024

CAPABILITIES = {
    "public_market_data_collection": True,
    "strategy_evaluation": False,
    "discovery": False,
    "candidate_promotion": False,
    "phase_r": False,
    "paper_trading": False,
    "live_trading": False,
    "order_submission": False,
    "capital_allocation": False,
    "registry_write": False,
    "service_control": False,
    "deployment": False,
    "interlock_release": False,
}

ADAPTER_AUTHORITIES = {
    "collector": False,
    "strategy_generation": False,
    "discovery": False,
    "candidate_or_validation": False,
    "phase_r": False,
    "paper_or_live": False,
    "order_or_capital": False,
    "registry_ingest": False,
    "service_or_deployment": False,
    "interlock_release": False,
}


class ClockBoundCollectorError(RuntimeError):
    """Stable fail-closed collector error."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        char in "0123456789abcdef" for char in value
    )


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ClockBoundCollectorError("duplicate_json_key")
        value[key] = item
    return value


def _read_regular_nofollow(path: Path, *, maximum: int, code: str) -> bytes:
    if not path.is_absolute() or str(path.resolve(strict=False)) != str(path):
        raise ClockBoundCollectorError(f"{code}_path_invalid")
    if not hasattr(os, "O_NOFOLLOW"):
        raise ClockBoundCollectorError(f"{code}_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise ClockBoundCollectorError(f"{code}_open_failed") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ClockBoundCollectorError(f"{code}_not_regular_or_too_large")
        chunks = []
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            before.st_size != len(raw)
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise ClockBoundCollectorError(f"{code}_changed_while_reading")
        return raw
    finally:
        os.close(descriptor)


def _path_in_home(value: Any, hermes_home: Path, code: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ClockBoundCollectorError(code)
    path = Path(value)
    if not path.is_absolute() or str(path.resolve(strict=False)) != value:
        raise ClockBoundCollectorError(code)
    try:
        path.relative_to(hermes_home)
    except ValueError as exc:
        raise ClockBoundCollectorError(code) from exc
    return path


def _file_sha256(path: Path, code: str) -> str:
    return sha256_bytes(
        _read_regular_nofollow(path, maximum=2 * 1024 * 1024, code=code)
    )


def load_contract(
    path: Path,
    *,
    expected_sha256: str,
    hermes_home: Path,
    collector_path: Path,
) -> dict[str, Any]:
    raw = _read_regular_nofollow(
        path, maximum=MAX_CONTRACT_BYTES, code="collector_contract"
    )
    if not _is_sha256(expected_sha256) or sha256_bytes(raw) != expected_sha256:
        raise ClockBoundCollectorError("collector_contract_hash_mismatch")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClockBoundCollectorError("collector_contract_json_invalid") from exc
    expected_keys = {
        "schema_version",
        "status",
        "stream_id",
        "endpoint",
        "coin",
        "interval",
        "period_ms",
        "authorized_slot_end_ms",
        "minimum_delay_ms",
        "maximum_delay_ms",
        "maximum_http_requests_per_slot",
        "automatic_retries",
        "redirects",
        "proxy_url",
        "collector_path",
        "collector_sha256",
        "adapter_path",
        "adapter_sha256",
        "source_contract_sha256",
        "intents_root",
        "acquisitions_root",
        "capabilities",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ClockBoundCollectorError("collector_contract_shape_invalid")
    if (
        value["schema_version"] != CONTRACT_SCHEMA
        or value["status"] != CONTRACT_STATUS
        or value["stream_id"] != "hyperliquid-btc-15m-clock-bound-raw-v1"
        or value["endpoint"] != ENDPOINT
        or value["coin"] != "BTC"
        or value["interval"] != "15m"
        or value["period_ms"] != PERIOD_MS
        or value["maximum_http_requests_per_slot"] != 1
        or value["automatic_retries"] != 0
        or value["redirects"] != 0
        or value["proxy_url"] != "http://127.0.0.1:28990"
        or value["capabilities"] != CAPABILITIES
    ):
        raise ClockBoundCollectorError("collector_contract_policy_invalid")
    slots = value["authorized_slot_end_ms"]
    if (
        not isinstance(slots, list)
        or not slots
        or len(slots) > 16
        or any(isinstance(slot, bool) or not isinstance(slot, int) for slot in slots)
        or slots != sorted(set(slots))
        or any(slot <= 0 or slot % PERIOD_MS for slot in slots)
        or any(right - left != PERIOD_MS for left, right in zip(slots, slots[1:]))
    ):
        raise ClockBoundCollectorError("collector_contract_slots_invalid")
    minimum_delay = value["minimum_delay_ms"]
    maximum_delay = value["maximum_delay_ms"]
    if (
        isinstance(minimum_delay, bool)
        or not isinstance(minimum_delay, int)
        or isinstance(maximum_delay, bool)
        or not isinstance(maximum_delay, int)
        or minimum_delay < 30_000
        or maximum_delay > 5 * 60_000
        or minimum_delay >= maximum_delay
    ):
        raise ClockBoundCollectorError("collector_contract_delay_invalid")
    expected_collector_path = _path_in_home(
        value["collector_path"], hermes_home, "collector_path_invalid"
    )
    if expected_collector_path != collector_path:
        raise ClockBoundCollectorError("collector_path_binding_mismatch")
    if (
        not _is_sha256(value["collector_sha256"])
        or _file_sha256(collector_path, "collector_source")
        != value["collector_sha256"]
    ):
        raise ClockBoundCollectorError("collector_source_hash_mismatch")
    adapter_path = _path_in_home(
        value["adapter_path"], hermes_home, "adapter_path_invalid"
    )
    if (
        not _is_sha256(value["adapter_sha256"])
        or _file_sha256(adapter_path, "adapter_source") != value["adapter_sha256"]
        or not _is_sha256(value["source_contract_sha256"])
    ):
        raise ClockBoundCollectorError("adapter_or_source_binding_invalid")
    _path_in_home(value["intents_root"], hermes_home, "intents_root_invalid")
    _path_in_home(
        value["acquisitions_root"], hermes_home, "acquisitions_root_invalid"
    )
    return value


def select_slot(contract: Mapping[str, Any], now_ms: int) -> int | None:
    if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
        raise ClockBoundCollectorError("now_ms_invalid")
    for slot in contract["authorized_slot_end_ms"]:
        if slot + contract["minimum_delay_ms"] <= now_ms <= slot + contract["maximum_delay_ms"]:
            return slot
    return None


def _write_exclusive(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _load_adapter(path: Path):
    spec = importlib.util.spec_from_file_location("clock_bound_candle_adapter", path)
    if spec is None or spec.loader is None:
        raise ClockBoundCollectorError("adapter_import_failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _slot_id(slot_end_ms: int) -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(slot_end_ms / 1000))


def run_once(
    contract: Mapping[str, Any],
    *,
    now_ms: int,
    capture_fn: Callable[..., Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    slot_end = select_slot(contract, now_ms)
    if slot_end is None:
        return {"status": "NO_AUTHORIZED_SLOT_DUE"}
    run_id = f"hyperliquid-candle-btc-15m-clock-{_slot_id(slot_end)}"
    intents_root = Path(contract["intents_root"])
    acquisitions_root = Path(contract["acquisitions_root"])
    intent_path = intents_root / run_id / "run-intent.json"
    output_dir = acquisitions_root / run_id
    marker_path = acquisitions_root / f".{run_id}.consumed"
    receipt_path = output_dir / "receipt.json"
    if receipt_path.is_file() and not receipt_path.is_symlink():
        return {"status": "SLOT_ALREADY_CAPTURED", "run_id": run_id}
    if intent_path.exists() or intent_path.is_symlink() or output_dir.exists() or marker_path.exists():
        raise ClockBoundCollectorError("slot_namespace_exists_without_complete_receipt")
    request = {
        "type": "candleSnapshot",
        "req": {
            "coin": "BTC",
            "interval": "15m",
            "startTime": slot_end - PERIOD_MS,
            "endTime": slot_end,
        },
    }
    intent = {
        "schema_version": RUN_INTENT_SCHEMA,
        "run_id": run_id,
        "command": COMMAND,
        "endpoint": ENDPOINT,
        "request": request,
        "request_sha256": sha256_bytes(canonical_bytes(request)),
        "output_dir": str(output_dir),
        "consumption_marker_path": str(marker_path),
        "adapter_sha256": contract["adapter_sha256"],
        "source_contract_sha256": contract["source_contract_sha256"],
        "maximum_http_requests": 1,
        "retries": 0,
        "redirects": 0,
        "network_fetch": True,
        "authorities": ADAPTER_AUTHORITIES,
    }
    intent_raw = canonical_bytes(intent) + b"\n"
    _write_exclusive(intent_path, intent_raw)
    intent_sha256 = sha256_bytes(intent_raw)
    proxy = contract["proxy_url"]
    os.environ["HTTPS_PROXY"] = proxy
    os.environ["https_proxy"] = proxy
    os.environ["NO_PROXY"] = ""
    os.environ["no_proxy"] = ""
    if capture_fn is None:
        adapter = _load_adapter(Path(contract["adapter_path"]))
        if adapter.SOURCE_CONTRACT_SHA256 != contract["source_contract_sha256"]:
            raise ClockBoundCollectorError("adapter_source_contract_runtime_mismatch")
        capture_fn = adapter.capture_candles
    result = capture_fn(
        interval="15m",
        start_time_ms=slot_end - PERIOD_MS,
        end_time_ms=slot_end,
        output_dir=str(output_dir),
        run_intent=str(intent_path),
        run_intent_hash=intent_sha256,
        adapter_path=Path(contract["adapter_path"]),
    )
    return {
        "status": "CLOCK_BOUND_RAW_CAPTURE_COMPLETED",
        "run_id": run_id,
        "slot_end_ms": slot_end,
        "run_intent_sha256": intent_sha256,
        "receipt_path": str(receipt_path),
        "adapter_result": dict(result),
        "strategy_or_trading_authority": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--hermes-home", default=os.environ.get("HERMES_HOME", ""))
    args = parser.parse_args(argv)
    try:
        hermes_home = Path(args.hermes_home)
        collector_path = Path(__file__).resolve()
        contract = load_contract(
            Path(args.contract),
            expected_sha256=args.contract_sha256,
            hermes_home=hermes_home,
            collector_path=collector_path,
        )
        result = run_once(contract, now_ms=int(time.time() * 1000))
    except (ClockBoundCollectorError, OSError) as exc:
        print(
            canonical_bytes(
                {"status": "CLOCK_BOUND_COLLECTOR_FAILED_NO_RETRY", "error": str(exc)}
            ).decode("utf-8"),
            file=sys.stderr,
        )
        return 2
    if result["status"] in {"NO_AUTHORIZED_SLOT_DUE", "SLOT_ALREADY_CAPTURED"}:
        print("DONT_NOTIFY")
    else:
        print(canonical_bytes(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
