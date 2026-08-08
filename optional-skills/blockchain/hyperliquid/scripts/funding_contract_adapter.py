#!/usr/bin/env python3
"""One-shot, raw-first Hyperliquid funding acquisition control path.

This module is deliberately isolated from the normal Hyperliquid helper.  It
does not grant acquisition authority: a separately issued, hash-bound owner
authorization receipt is required before its single HTTP request can run.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional


ENDPOINT = "https://api.hyperliquid.xyz/info"
COMMAND = "funding-contract"
TIMEOUT_SECONDS = 20
AUTHORIZATION_SCHEMA = "hermes.hyperliquid.funding-contract-authorization.v1"
RECEIPT_SCHEMA = "hermes.hyperliquid.funding-contract-receipt.v1"
AUTHORIZATION_HASH_ENV = "HERMES_FUNDING_CONTRACT_AUTHORIZATION_SHA256"
REQUIRED_FIELDS = ("coin", "fundingRate", "premium", "time")
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
AUTHORIZATION_KEYS = {
    "schema_version",
    "authorization_id",
    "command",
    "endpoint",
    "source_contract_sha256",
    "request_sha256",
    "coin",
    "start_time_ms",
    "end_time_ms",
    "output_dir",
    "consumption_marker_path",
    "maximum_http_requests",
    "adapter_sha256",
    "entrypoint_sha256",
    "network_fetch",
    "authorities",
}


class FundingContractError(RuntimeError):
    """Fail-closed control-path error."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(char in "0123456789abcdef" for char in value)


def _canonical_absolute_path(value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise FundingContractError("authorization_path_missing")
    path = Path(value)
    if not path.is_absolute() or str(path.resolve(strict=False)) != value:
        raise FundingContractError("authorization_path_not_canonical_absolute")
    return path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive_marker(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = _canonical_json_bytes(payload) + b"\n"
    try:
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise FundingContractError("authorization_already_consumed") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        _fsync_directory(path.parent)


def _publish_bytes(path: Path, data: bytes) -> None:
    """Publish complete bytes without overwriting an existing final path."""
    if path.exists():
        raise FundingContractError(f"output_collision:{path.name}")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(str(temporary), str(path))
        except FileExistsError as exc:
            raise FundingContractError(f"output_collision:{path.name}") from exc
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _source_sha256(path: Path) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise FundingContractError(f"source_unreadable:{path}") from exc


def build_request(coin: str, start_time_ms: int, end_time_ms: int) -> Dict[str, Any]:
    if not isinstance(coin, str) or not coin or coin != coin.strip():
        raise FundingContractError("coin_must_be_exact_nonempty_string")
    if isinstance(start_time_ms, bool) or not isinstance(start_time_ms, int):
        raise FundingContractError("start_time_ms_must_be_integer")
    if isinstance(end_time_ms, bool) or not isinstance(end_time_ms, int):
        raise FundingContractError("end_time_ms_must_be_integer")
    if start_time_ms < 0 or start_time_ms >= end_time_ms:
        raise FundingContractError("invalid_half_open_window")
    return {
        "coin": coin,
        "endTime": end_time_ms,
        "startTime": start_time_ms,
        "type": "fundingHistory",
    }


def _load_authorization(
    path: Path,
    *,
    expected_hash: str,
    request: Dict[str, Any],
    output_dir: Path,
    adapter_path: Path,
    entrypoint_path: Path,
) -> tuple[Dict[str, Any], str, Path]:
    try:
        raw = path.read_bytes()
        authorization = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise FundingContractError("authorization_unreadable_or_invalid_json") from exc
    actual_hash = _sha256_bytes(raw)
    if not _is_sha256(expected_hash) or actual_hash != expected_hash:
        raise FundingContractError("authorization_hash_mismatch")
    if not isinstance(authorization, dict):
        raise FundingContractError("authorization_must_be_object")
    if set(authorization) != AUTHORIZATION_KEYS:
        raise FundingContractError("authorization_shape_invalid")

    request_bytes = _canonical_json_bytes(request)
    required = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "command": COMMAND,
        "endpoint": ENDPOINT,
        "request_sha256": _sha256_bytes(request_bytes),
        "coin": request["coin"],
        "start_time_ms": request["startTime"],
        "end_time_ms": request["endTime"],
        "output_dir": str(output_dir),
        "maximum_http_requests": 1,
        "adapter_sha256": _source_sha256(adapter_path),
        "entrypoint_sha256": _source_sha256(entrypoint_path),
    }
    for key, value in required.items():
        if authorization.get(key) != value:
            raise FundingContractError(f"authorization_binding_mismatch:{key}")
    authorization_id = authorization.get("authorization_id")
    if not isinstance(authorization_id, str) or not authorization_id:
        raise FundingContractError("authorization_id_missing")
    if authorization.get("network_fetch") is not True:
        raise FundingContractError("network_fetch_not_authorized")
    if not _is_sha256(authorization.get("source_contract_sha256")):
        raise FundingContractError("source_contract_sha256_invalid")
    authorities = authorization.get("authorities")
    if not isinstance(authorities, dict) or set(authorities) != set(AUTHORITY_KEYS):
        raise FundingContractError("authorization_authority_shape_invalid")
    if any(authorities.get(key) is not False for key in AUTHORITY_KEYS):
        raise FundingContractError("non_acquisition_authority_present")
    marker = _canonical_absolute_path(authorization.get("consumption_marker_path"))
    return authorization, actual_hash, marker


def _open_once(request: urllib.request.Request, timeout: int):
    opener = urllib.request.build_opener(_NoRedirect())
    return opener.open(request, timeout=timeout)


def _capture_once(
    request_bytes: bytes,
    *,
    raw_path: Path,
    open_once: Callable[[urllib.request.Request, int], Any],
) -> Dict[str, Any]:
    request = urllib.request.Request(
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
        with open_once(request, TIMEOUT_SECONDS) as response:
            status = int(getattr(response, "status", response.getcode()))
            content_type = response.headers.get("Content-Type", "")
            content_encoding = response.headers.get("Content-Encoding", "")
            body = response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FundingContractError(f"single_request_failed:{type(exc).__name__}") from exc
    if status != 200:
        raise FundingContractError(f"unexpected_http_status:{status}")
    if not content_type.lower().startswith("application/json"):
        raise FundingContractError("unexpected_content_type")
    _publish_bytes(raw_path, body)
    persisted = raw_path.read_bytes()
    if persisted != body:
        raise FundingContractError("persisted_raw_bytes_mismatch")
    return {
        "http_status": status,
        "content_type": content_type,
        "content_encoding": content_encoding,
        "raw_sha256": _sha256_bytes(persisted),
        "raw_bytes": persisted,
    }


def _structural_summary(payload: Any, request: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, list):
        raise FundingContractError("response_must_be_array")
    previous_time: Optional[int] = None
    identities: Dict[tuple[str, int], bytes] = {}
    duplicate_count = 0
    conflict_count = 0
    event_times = []
    for row in payload:
        if not isinstance(row, dict) or set(row) != set(REQUIRED_FIELDS):
            raise FundingContractError("funding_row_schema_invalid")
        if row.get("coin") != request["coin"]:
            raise FundingContractError("funding_row_coin_mismatch")
        event_time = row.get("time")
        if isinstance(event_time, bool) or not isinstance(event_time, int):
            raise FundingContractError("funding_row_time_invalid")
        if not request["startTime"] <= event_time < request["endTime"]:
            raise FundingContractError("funding_row_outside_half_open_window")
        if previous_time is not None and event_time < previous_time:
            raise FundingContractError("funding_rows_not_monotonic")
        if not isinstance(row.get("fundingRate"), str) or not isinstance(row.get("premium"), str):
            raise FundingContractError("funding_row_numeric_representation_invalid")
        identity = (row["coin"], event_time)
        row_bytes = _canonical_json_bytes(row)
        prior = identities.get(identity)
        if prior is not None:
            duplicate_count += 1
            if prior != row_bytes:
                conflict_count += 1
        else:
            identities[identity] = row_bytes
        previous_time = event_time
        event_times.append(event_time)
    if duplicate_count:
        raise FundingContractError(
            "funding_identity_conflict" if conflict_count else "funding_duplicate_identity"
        )
    return {
        "row_count": len(payload),
        "schema": list(REQUIRED_FIELDS),
        "min_event_time": min(event_times) if event_times else None,
        "max_event_time": max(event_times) if event_times else None,
        "duplicate_count": duplicate_count,
        "conflict_count": conflict_count,
        "completeness_status": "NOT_PROVEN",
    }


def execute_funding_contract(
    *,
    coin: str,
    start_time_ms: int,
    end_time_ms: int,
    output_dir: str,
    authorization_receipt: str,
    adapter_path: Path,
    entrypoint_path: Path,
    authorization_hash: Optional[str] = None,
    open_once: Callable[[urllib.request.Request, int], Any] = _open_once,
) -> Dict[str, Any]:
    request = build_request(coin, start_time_ms, end_time_ms)
    request_bytes = _canonical_json_bytes(request)
    target_dir = _canonical_absolute_path(output_dir)
    authorization_path = _canonical_absolute_path(authorization_receipt)
    expected_hash = authorization_hash or os.environ.get(AUTHORIZATION_HASH_ENV, "")
    authorization, authorization_sha256, marker_path = _load_authorization(
        authorization_path,
        expected_hash=expected_hash,
        request=request,
        output_dir=target_dir,
        adapter_path=adapter_path,
        entrypoint_path=entrypoint_path,
    )

    if marker_path.exists():
        raise FundingContractError("authorization_already_consumed")
    if marker_path == target_dir or target_dir in marker_path.parents:
        raise FundingContractError("consumption_marker_must_be_outside_output_dir")
    if target_dir.exists():
        raise FundingContractError("output_dir_must_not_exist")

    marker = {
        "schema_version": "hermes.hyperliquid.funding-contract-consumption.v1",
        "authorization_id": authorization["authorization_id"],
        "authorization_sha256": authorization_sha256,
        "request_sha256": _sha256_bytes(request_bytes),
        "state": "CONSUMED_BEFORE_HTTP",
    }
    _write_exclusive_marker(marker_path, marker)
    try:
        target_dir.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise FundingContractError("output_dir_must_not_exist") from exc
    _fsync_directory(target_dir.parent)

    request_path = target_dir / "request.json"
    raw_path = target_dir / "response.raw"
    receipt_path = target_dir / "receipt.json"
    _publish_bytes(request_path, request_bytes)
    capture = _capture_once(request_bytes, raw_path=raw_path, open_once=open_once)
    terminal_status = "RAW_CAPTURED_JSON_INVALID"
    try:
        parsed = json.loads(raw_path.read_bytes())
        summary = _structural_summary(parsed, request)
        terminal_status = "RAW_ACQUIRED_STRUCTURE_PASS_COMPLETENESS_NOT_PROVEN"
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        summary = {
            "row_count": None,
            "schema": None,
            "min_event_time": None,
            "max_event_time": None,
            "duplicate_count": None,
            "conflict_count": None,
            "completeness_status": "NOT_PROVEN",
            "technical_error": str(exc),
        }
    except FundingContractError as exc:
        terminal_status = "RAW_CAPTURED_STRUCTURE_INVALID"
        summary = {
            "row_count": None,
            "schema": None,
            "min_event_time": None,
            "max_event_time": None,
            "duplicate_count": None,
            "conflict_count": None,
            "completeness_status": "NOT_PROVEN",
            "technical_error": str(exc),
        }

    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "status": terminal_status,
        "source": {"endpoint": ENDPOINT, "method": "POST", "query_type": "fundingHistory"},
        "request": {
            "path": str(request_path),
            "sha256": _sha256_bytes(request_bytes),
            "coin": coin,
            "start_time_ms": start_time_ms,
            "end_time_ms": end_time_ms,
        },
        "authorization": {
            "id": authorization["authorization_id"],
            "sha256": authorization_sha256,
            "source_contract_sha256": authorization["source_contract_sha256"],
            "consumed_before_http": True,
        },
        "transport": {
            "http_requests": 1,
            "automatic_retries": 0,
            "redirects_allowed": False,
            "timeout_seconds": TIMEOUT_SECONDS,
            "http_status": capture["http_status"],
            "content_type": capture["content_type"],
            "content_encoding": capture["content_encoding"],
        },
        "raw": {"path": str(raw_path), "sha256": capture["raw_sha256"]},
        "structure": summary,
        "claim_boundary": {
            "raw_acquired": True,
            "completeness_proven": False,
            "source_semantics_ready": False,
            "causal_research_ready": False,
            "strategy_authorized": False,
            "trading_authorized": False,
        },
    }
    _publish_bytes(receipt_path, _canonical_json_bytes(receipt) + b"\n")
    return {
        "status": terminal_status,
        "output_dir": str(target_dir),
        "raw_path": str(raw_path),
        "request_path": str(request_path),
        "receipt_path": str(receipt_path),
        "request_sha256": _sha256_bytes(request_bytes),
        "raw_sha256": capture["raw_sha256"],
        "strategy_authorized": False,
        "trading_authorized": False,
    }
