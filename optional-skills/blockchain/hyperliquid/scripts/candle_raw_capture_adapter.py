#!/usr/bin/env python3
"""One-shot, raw-first Hyperliquid BTC candle capture.

This adapter is intentionally narrower than ``hyperliquid_client.py``.  It
uses one public ``/info`` request, persists the exact request and response
bytes, and exposes only structural, local-boundary rows.  It has no
strategy, trading, account, or service-control authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Mapping, Optional


ENDPOINT = "https://api.hyperliquid.xyz/info"
COMMAND = "candle-raw-capture"
TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
RUN_INTENT_SCHEMA = "hermes.hyperliquid.candle-raw-capture-run-intent.v1"
CONSUMPTION_SCHEMA = "hermes.hyperliquid.candle-raw-capture-consumption.v1"
RECEIPT_SCHEMA = "hermes.hyperliquid.candle-raw-capture-receipt.v1"
RUN_INTENT_HASH_ENV = "HERMES_HYPERLIQUID_CANDLE_RUN_INTENT_SHA256"

RAW_CANDLE_FIELDS = ("t", "T", "s", "i", "o", "h", "l", "c", "v", "n")
RAW_CANDLE_FIELD_SET = frozenset(RAW_CANDLE_FIELDS)
NUMERIC_TEXT_FIELDS = frozenset({"o", "h", "l", "c", "v"})
AUTHORITY_KEYS = (
    "collector",
    "strategy_generation",
    "discovery",
    "candidate_or_validation",
    "phase_r",
    "paper_or_live",
    "order_or_capital",
    "registry_ingest",
    "service_or_deployment",
    "interlock_release",
)
ALL_AUTHORITIES_FALSE = {key: False for key in AUTHORITY_KEYS}

# Presence, including an empty value, is denied before any socket is opened.
CREDENTIAL_ENV_DENYLIST = frozenset(
    {
        "API_KEY",
        "API_SECRET",
        "HYPERLIQUID_API_KEY",
        "HYPERLIQUID_API_SECRET",
        "HYPERLIQUID_PRIVATE_KEY",
        "HYPERLIQUID_SECRET",
        "HYPERLIQUID_USER_ADDRESS",
        "HYPERLIQUID_WALLET_ADDRESS",
        "HYPERLIQUID_WALLET_PRIVATE_KEY",
        "HL_PRIVATE_KEY",
        "PRIVATE_KEY",
        "SECRET_KEY",
        "TRADING_PRIVATE_KEY",
        "TRADING_API_KEY",
        "TRADING_API_SECRET",
        "EXCHANGE_PRIVATE_KEY",
        "EXCHANGE_API_KEY",
        "BROKER_API_KEY",
        "ORDER_API_KEY",
        "ORDER_SIGNING_KEY",
        "CAPITAL_ALLOCATION_TOKEN",
        "LIVE_TRADING",
        "PAPER_TRADING",
        "ORDER_SUBMISSION",
        "CAPITAL_ALLOCATION",
        "BROKER_URL",
        "TRADING_BASE_URL",
        "WALLET_PRIVATE_KEY",
    }
)


class CandleCaptureError(RuntimeError):
    """Fail-closed capture error."""


class _DuplicateJSONKey(ValueError):
    pass


def _canonical_bytes(value: Any) -> bytes:
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
            raise _DuplicateJSONKey(key)
        value[key] = item
    return value


def _strict_json_loads(raw: bytes) -> Any:
    return json.loads(raw, object_pairs_hook=_reject_duplicate_keys)


def _read_strict_json_nofollow(path: Path) -> tuple[dict[str, Any], str]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise CandleCaptureError("run_intent_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise CandleCaptureError("run_intent_unreadable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CandleCaptureError("run_intent_not_regular")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            after.st_size != len(raw)
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise CandleCaptureError("run_intent_changed_while_reading")
    except CandleCaptureError:
        raise
    except OSError as exc:
        raise CandleCaptureError("run_intent_unreadable") from exc
    finally:
        os.close(descriptor)
    try:
        value = _strict_json_loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, _DuplicateJSONKey) as exc:
        raise CandleCaptureError("run_intent_unreadable_or_invalid") from exc
    if not isinstance(value, dict):
        raise CandleCaptureError("run_intent_must_be_object")
    return value, sha256_bytes(raw)


def _canonical_path(value: Any, code: str) -> Path:
    if not isinstance(value, str) or not value:
        raise CandleCaptureError(code)
    path = Path(value)
    if not path.is_absolute() or str(path.resolve(strict=False)) != value:
        raise CandleCaptureError(code)
    return path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, data: bytes, code: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(
            str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
    except FileExistsError as exc:
        raise CandleCaptureError(code) from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        _fsync_directory(path.parent)


def _publish_exclusive(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise CandleCaptureError(f"output_collision:{path.name}")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        descriptor = os.open(
            str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(str(temporary), str(path))
        except FileExistsError as exc:
            raise CandleCaptureError(f"output_collision:{path.name}") from exc
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _source_sha256(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise CandleCaptureError(f"source_unreadable:{path}") from exc


SOURCE_CONTRACT = {
    "schema_version": "hyperliquid-btc-candle-raw-source-contract-v1",
    "endpoint": ENDPOINT,
    "method": "POST",
    "query_type": "candleSnapshot",
    "coin": "BTC",
    "raw_fields": list(RAW_CANDLE_FIELDS),
    "event_time_field": "t",
    "close_time_field": "T",
    "event_time_unit": "unix_ms",
    "local_completion_rule": "T < request_start_wall_ms",
    "source_claims": "UNKNOWN_REVIEW_REQUIRED",
}
SOURCE_CONTRACT_SHA256 = sha256_bytes(_canonical_bytes(SOURCE_CONTRACT))


def build_request(*, interval: str, start_time_ms: int, end_time_ms: int) -> Dict[str, Any]:
    if not isinstance(interval, str) or not interval or interval != interval.strip():
        raise CandleCaptureError("interval_invalid")
    if isinstance(start_time_ms, bool) or not isinstance(start_time_ms, int):
        raise CandleCaptureError("start_time_ms_invalid")
    if isinstance(end_time_ms, bool) or not isinstance(end_time_ms, int):
        raise CandleCaptureError("end_time_ms_invalid")
    if start_time_ms < 0 or start_time_ms >= end_time_ms:
        raise CandleCaptureError("invalid_half_open_window")
    return {
        "type": "candleSnapshot",
        "req": {
            "coin": "BTC",
            "interval": interval,
            "startTime": start_time_ms,
            "endTime": end_time_ms,
        },
    }


def _validate_run_intent(
    path: Path,
    *,
    expected_hash: str,
    request: Mapping[str, Any],
    output_dir: Path,
    marker_path: Path,
    adapter_path: Path,
) -> tuple[dict[str, Any], str]:
    intent, actual_hash = _read_strict_json_nofollow(path)
    if not _is_sha256(expected_hash) or actual_hash != expected_hash:
        raise CandleCaptureError("run_intent_hash_mismatch")
    if not isinstance(intent, dict):
        raise CandleCaptureError("run_intent_must_be_object")
    expected_keys = {
        "schema_version", "run_id", "command", "endpoint", "request",
        "request_sha256", "output_dir", "consumption_marker_path",
        "adapter_sha256", "source_contract_sha256", "maximum_http_requests",
        "retries", "redirects", "network_fetch", "authorities",
    }
    if set(intent) != expected_keys:
        raise CandleCaptureError("run_intent_shape_invalid")
    request_dict = dict(request)
    required = {
        "schema_version": RUN_INTENT_SCHEMA,
        "command": COMMAND,
        "endpoint": ENDPOINT,
        "request": request_dict,
        "request_sha256": sha256_bytes(_canonical_bytes(request_dict)),
        "output_dir": str(output_dir),
        "consumption_marker_path": str(marker_path),
        "adapter_sha256": _source_sha256(adapter_path),
        "source_contract_sha256": SOURCE_CONTRACT_SHA256,
        "maximum_http_requests": 1,
        "retries": 0,
        "redirects": 0,
        "network_fetch": True,
        "authorities": ALL_AUTHORITIES_FALSE,
    }
    for key, value in required.items():
        if intent.get(key) != value:
            raise CandleCaptureError(f"run_intent_binding_mismatch:{key}")
    if not isinstance(intent.get("run_id"), str) or not intent["run_id"].strip():
        raise CandleCaptureError("run_id_invalid")
    return intent, actual_hash


def _deny_credentials() -> None:
    present = sorted(key for key in CREDENTIAL_ENV_DENYLIST if key in os.environ)
    if present:
        raise CandleCaptureError("credential_env_denied:" + ",".join(present))


def _write_consumption_marker(
    path: Path, *, run_id: str, run_intent_sha256: str, request_sha256: str
) -> None:
    payload = {
        "schema_version": CONSUMPTION_SCHEMA,
        "run_id": run_id,
        "run_intent_sha256": run_intent_sha256,
        "request_sha256": request_sha256,
        "state": "CONSUMED_BEFORE_HTTP",
    }
    _write_exclusive(path, _canonical_bytes(payload) + b"\n", "run_intent_already_consumed")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_once(request: urllib.request.Request, timeout: int) -> Any:
    return urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout)


def _validate_raw_rows(
    payload: Any, *, interval: str, request_start_wall_ms: int, response_complete_wall_ms: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(payload, list):
        raise CandleCaptureError("response_must_be_array")
    rows: list[dict[str, Any]] = []
    seen: dict[tuple[str, int], bytes] = {}
    previous_t: Optional[int] = None
    for raw in payload:
        if not isinstance(raw, dict) or set(raw) != RAW_CANDLE_FIELD_SET:
            raise CandleCaptureError("candle_row_exact_schema_invalid")
        if raw["s"] != "BTC" or raw["i"] != interval:
            raise CandleCaptureError("candle_row_identity_invalid")
        for key in ("t", "T", "n"):
            if isinstance(raw[key], bool) or not isinstance(raw[key], int) or raw[key] < 0:
                raise CandleCaptureError(f"candle_row_{key}_invalid")
        if raw["T"] <= raw["t"]:
            raise CandleCaptureError("candle_row_close_not_after_open")
        for key in NUMERIC_TEXT_FIELDS:
            if (
                not isinstance(raw[key], str)
                or not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", raw[key])
            ):
                raise CandleCaptureError(f"candle_row_{key}_invalid")
        if previous_t is not None and raw["t"] < previous_t:
            raise CandleCaptureError("candle_rows_not_monotonic")
        identity = (raw["s"], raw["t"])
        encoded = _canonical_bytes(raw)
        if identity in seen:
            raise CandleCaptureError(
                "candle_identity_conflict"
                if seen[identity] != encoded
                else "candle_duplicate_identity"
            )
        seen[identity] = encoded
        previous_t = raw["t"]
        if raw["T"] < request_start_wall_ms:
            rows.append(
                {
                    "row_number": len(rows) + 1,
                    "event_time_ms": raw["t"],
                    "close_time_ms": raw["T"],
                    "local_close_boundary_elapsed_ms": request_start_wall_ms - raw["T"],
                    "raw": raw,
                }
            )
    return rows, {
        "row_count": len(payload),
        "completed_row_count": len(rows),
        "excluded_open_rows": len(payload) - len(rows),
        "source_publication": "UNKNOWN/REVIEW_REQUIRED",
        "availability": "UNKNOWN/REVIEW_REQUIRED",
        "native_sequence": "UNKNOWN/REVIEW_REQUIRED",
        "completeness": "UNKNOWN/REVIEW_REQUIRED",
        "gap_count": None,
        "duplicate_count": 0,
        "response_complete_wall_ms": response_complete_wall_ms,
    }


def capture_candles(
    *,
    interval: str,
    start_time_ms: int,
    end_time_ms: int,
    output_dir: str,
    run_intent: str,
    run_intent_hash: Optional[str] = None,
    authorization_hash_env: str = RUN_INTENT_HASH_ENV,
    adapter_path: Optional[Path] = None,
    open_once: Callable[[urllib.request.Request, int], Any] = _open_once,
    wall_ms: Callable[[], int] = lambda: int(time.time() * 1000),
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> Dict[str, Any]:
    """Perform one authorized request and publish raw-first evidence."""
    _deny_credentials()
    request = build_request(interval=interval, start_time_ms=start_time_ms, end_time_ms=end_time_ms)
    request_bytes = _canonical_bytes(request)
    request_sha256 = sha256_bytes(request_bytes)
    target_dir = _canonical_path(output_dir, "output_dir_invalid")
    intent_path = _canonical_path(run_intent, "run_intent_path_invalid")
    marker_path = _canonical_path(
        str(target_dir.parent / f".{target_dir.name}.consumed"),
        "consumption_marker_path_invalid",
    )
    source_path = adapter_path or Path(__file__)
    expected_hash = run_intent_hash or os.environ.get(authorization_hash_env, "")
    intent, intent_sha256 = _validate_run_intent(
        intent_path,
        expected_hash=expected_hash,
        request=request,
        output_dir=target_dir,
        marker_path=marker_path,
        adapter_path=source_path,
    )
    _write_consumption_marker(
        marker_path,
        run_id=intent["run_id"],
        run_intent_sha256=intent_sha256,
        request_sha256=request_sha256,
    )
    if target_dir.exists():
        raise CandleCaptureError("output_dir_must_not_exist")
    target_dir.mkdir(mode=0o700)
    _fsync_directory(target_dir.parent)
    request_path = target_dir / "request.json"
    raw_path = target_dir / "response.raw"
    receipt_path = target_dir / "receipt.json"
    _write_exclusive(request_path, request_bytes, "request_output_collision")

    request_start_wall_ms = wall_ms()
    request_start_monotonic_ns = monotonic_ns()
    http_request = urllib.request.Request(
        ENDPOINT,
        data=request_bytes,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "HermesAgent/1.0",
        },
        method="POST",
    )
    try:
        with open_once(http_request, TIMEOUT_SECONDS) as response:
            status = int(getattr(response, "status", response.getcode()))
            content_type = response.headers.get("Content-Type", "")
            body = response.read(MAX_RESPONSE_BYTES + 1)
        response_complete_wall_ms = wall_ms()
        elapsed_ns = monotonic_ns() - request_start_monotonic_ns
        if response_complete_wall_ms < request_start_wall_ms:
            raise CandleCaptureError("wall_clock_rollback")
        if elapsed_ns < 0:
            raise CandleCaptureError("monotonic_clock_rollback")
    except urllib.error.HTTPError as exc:
        # Preserve an HTTP error body if the server supplied one; never retry.
        try:
            body = exc.read(MAX_RESPONSE_BYTES + 1)
        except OSError:
            body = b""
        if body:
            _write_exclusive(raw_path, body, "raw_output_collision")
        raise CandleCaptureError(f"single_request_failed:HTTP_{exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CandleCaptureError(f"single_request_failed:{type(exc).__name__}") from exc

    if status != 200:
        _write_exclusive(raw_path, body, "raw_output_collision")
        raise CandleCaptureError(f"unexpected_http_status:{status}")
    if not content_type.lower().startswith("application/json"):
        _write_exclusive(raw_path, body, "raw_output_collision")
        raise CandleCaptureError("unexpected_content_type")
    if len(body) > MAX_RESPONSE_BYTES:
        raise CandleCaptureError("response_cap_exceeded")
    _write_exclusive(raw_path, body, "raw_output_collision")
    if raw_path.read_bytes() != body:
        raise CandleCaptureError("persisted_raw_bytes_mismatch")

    try:
        payload = _strict_json_loads(body)
        rows, structure = _validate_raw_rows(
            payload,
            interval=interval,
            request_start_wall_ms=request_start_wall_ms,
            response_complete_wall_ms=response_complete_wall_ms,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, _DuplicateJSONKey) as exc:
        raise CandleCaptureError("raw_json_invalid") from exc
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "status": "RAW_CAPTURED_STRUCTURAL_ROWS_LOCAL_BOUNDARY_ONLY",
        "source": {
            "endpoint": ENDPOINT,
            "method": "POST",
            "query_type": "candleSnapshot",
            "adapter_sha256": _source_sha256(source_path),
            "source_contract_sha256": SOURCE_CONTRACT_SHA256,
        },
        "request": {
            "path": str(request_path),
            "sha256": request_sha256,
            "payload": request,
        },
        "run_intent": {
            "path": str(intent_path),
            "sha256": intent_sha256,
            "run_id": intent["run_id"],
        },
        "transport": {
            "http_requests": 1,
            "automatic_retries": 0,
            "redirects_allowed": 0,
            "timeout_seconds": TIMEOUT_SECONDS,
            "http_status": status,
            "content_type": content_type,
        },
        "timing": {
            "request_start_wall_ms": request_start_wall_ms,
            "response_complete_wall_ms": response_complete_wall_ms,
            "monotonic_elapsed_ns": elapsed_ns,
        },
        "raw": {
            "path": str(raw_path),
            "sha256": sha256_bytes(body),
            "bytes": len(body),
        },
        "structure": structure,
        "structural_rows": rows,
        "claim_boundary": {
            "network_fetch": True,
            "source_publication": "UNKNOWN/REVIEW_REQUIRED",
            "availability": "UNKNOWN/REVIEW_REQUIRED",
            "native_sequence": "UNKNOWN/REVIEW_REQUIRED",
            "completeness": "UNKNOWN/REVIEW_REQUIRED",
            "realtime": False,
            "causal": False,
            "strategy": False,
            "discovery": False,
            "candidate": False,
            "phase_r": False,
            "promotion": False,
            "paper": False,
            "live": False,
            "order": False,
            "capital": False,
            "service": False,
            "interlock": False,
        },
        "authorities": dict(ALL_AUTHORITIES_FALSE),
    }
    _publish_exclusive(receipt_path, _canonical_bytes(receipt) + b"\n")
    return {
        "status": receipt["status"],
        "output_dir": str(target_dir),
        "request_path": str(request_path),
        "raw_path": str(raw_path),
        "receipt_path": str(receipt_path),
        "raw_sha256": receipt["raw"]["sha256"],
        "request_sha256": request_sha256,
        "run_intent_sha256": intent_sha256,
        "completed_row_count": len(rows),
    }


def main(argv: Optional[list[str]] = None) -> int:
    """Run one exact owner-intent capture without enabling a scheduler."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", required=True)
    parser.add_argument("--start-time-ms", required=True, type=int)
    parser.add_argument("--end-time-ms", required=True, type=int)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--run-intent", required=True)
    parser.add_argument("--run-intent-sha256")
    args = parser.parse_args(argv)
    try:
        result = capture_candles(
            interval=args.interval,
            start_time_ms=args.start_time_ms,
            end_time_ms=args.end_time_ms,
            output_dir=args.output_dir,
            run_intent=args.run_intent,
            run_intent_hash=args.run_intent_sha256,
        )
    except CandleCaptureError as exc:
        error = {"status": "RAW_CAPTURE_FAILED_NO_RETRY", "error": str(exc)}
        print(_canonical_bytes(error).decode("utf-8"), file=sys.stderr)
        return 2
    print(_canonical_bytes(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
