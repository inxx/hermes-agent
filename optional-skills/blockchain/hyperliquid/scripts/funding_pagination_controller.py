#!/usr/bin/env python3
"""Offline-only bounded pagination control for Hyperliquid funding receipts.

This module consumes immutable one-shot receipts and emits review-bound request
intents.  It never opens a socket, creates an owner authorization, or parses
funding values.  A later page still requires a separately issued owner
authorization and the existing one-request adapter.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence


RECEIPT_SCHEMA = "hermes.hyperliquid.funding-contract-receipt.v2"
CONTROLLER_SCHEMA = "hermes.hyperliquid.funding-pagination-controller.v1"
INTENT_SCHEMA = "hermes.hyperliquid.funding-pagination-intent.v1"
ENDPOINT = "https://api.hyperliquid.xyz/info"
COMMAND = "funding-contract"
REQUIRED_FIELDS = ("coin", "fundingRate", "premium", "time")
NEXT_START_POLICY = "overlap_predecessor_max_event_time_review_required"
UNKNOWN_STATUS = "UNKNOWN/REVIEW_REQUIRED"
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


class FundingPaginationError(RuntimeError):
    """Fail-closed offline pagination error."""


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise FundingPaginationError(f"file_unreadable:{path}") from exc


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        char in "0123456789abcdef" for char in value
    )


def _absolute_path(value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise FundingPaginationError("path_missing")
    path = Path(value)
    if not path.is_absolute() or str(path.resolve(strict=False)) != value:
        raise FundingPaginationError("path_not_canonical_absolute")
    return path


def _exclusive_publish(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise FundingPaginationError(f"output_collision:{path.name}")
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
            raise FundingPaginationError(f"output_collision:{path.name}") from exc
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise FundingPaginationError(f"{name}_must_be_positive_integer")
    return value


def _load_json(path: Path, error: str) -> tuple[bytes, Dict[str, Any]]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FundingPaginationError(error) from exc
    if not isinstance(value, dict):
        raise FundingPaginationError(error)
    return raw, value


def _verify_raw(receipt: Dict[str, Any]) -> tuple[Path, str, int]:
    raw_info = receipt.get("raw")
    if not isinstance(raw_info, dict) or not _is_sha256(raw_info.get("sha256")):
        raise FundingPaginationError("predecessor_raw_integrity_missing")
    raw_path = _absolute_path(raw_info.get("path"))
    if raw_path.is_symlink():
        raise FundingPaginationError("predecessor_raw_symlink_rejected")
    try:
        raw_bytes = raw_path.read_bytes()
    except OSError as exc:
        raise FundingPaginationError("predecessor_raw_unreadable") from exc
    raw_sha256 = _sha256_bytes(raw_bytes)
    if raw_sha256 != raw_info["sha256"]:
        raise FundingPaginationError("predecessor_raw_integrity_mismatch")
    return raw_path, raw_sha256, len(raw_bytes)


def _row_set_hash(rows: Iterable[Dict[str, Any]]) -> str:
    canonical_rows = sorted(_canonical_bytes(row) for row in rows)
    return _sha256_bytes(b"[" + b",".join(canonical_rows) + b"]")


def _boundary_hashes(
    raw_path: Path, *, coin: str, min_time: Optional[int], max_time: Optional[int]
) -> tuple[Optional[str], Optional[str]]:
    try:
        payload = json.loads(raw_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FundingPaginationError("predecessor_raw_not_structurally_readable") from exc
    if not isinstance(payload, list):
        raise FundingPaginationError("predecessor_raw_not_array")
    rows: List[Dict[str, Any]] = []
    for row in payload:
        if not isinstance(row, dict) or set(row) != set(REQUIRED_FIELDS):
            raise FundingPaginationError("predecessor_raw_row_schema_invalid")
        if row.get("coin") != coin or not isinstance(row.get("time"), int):
            raise FundingPaginationError("predecessor_raw_row_identity_invalid")
        rows.append(row)
    if not rows:
        return None, None
    actual_min = min(row["time"] for row in rows)
    actual_max = max(row["time"] for row in rows)
    if actual_min != min_time or actual_max != max_time:
        raise FundingPaginationError("predecessor_raw_time_bounds_mismatch")
    return (
        _row_set_hash(row for row in rows if row["time"] == actual_min),
        _row_set_hash(row for row in rows if row["time"] == actual_max),
    )


def _verify_request(receipt: Dict[str, Any]) -> Dict[str, Any]:
    request_info = receipt.get("request")
    if not isinstance(request_info, dict) or not _is_sha256(request_info.get("sha256")):
        raise FundingPaginationError("predecessor_request_integrity_missing")
    request_path = _absolute_path(request_info.get("path"))
    if request_path.is_symlink():
        raise FundingPaginationError("predecessor_request_symlink_rejected")
    request_bytes, request_payload = _load_json(request_path, "predecessor_request_unreadable")
    request_sha256 = _sha256_bytes(_canonical_bytes(request_payload))
    if request_sha256 != request_info["sha256"]:
        raise FundingPaginationError("predecessor_request_hash_mismatch")
    if request_payload.get("type") != "fundingHistory":
        raise FundingPaginationError("predecessor_request_type_invalid")
    if request_info.get("sha256") != _sha256_bytes(request_bytes.rstrip(b"\n")):
        raise FundingPaginationError("predecessor_request_file_canonical_mismatch")
    return {
        "path": str(request_path),
        "sha256": request_info["sha256"],
        "payload": request_payload,
        "coin": request_info.get("coin"),
        "start_time_ms": request_info.get("start_time_ms"),
        "end_time_exclusive_ms": request_info.get("end_time_exclusive_ms"),
        "wire_end_inclusive_ms": request_info.get("wire_end_inclusive_ms"),
    }


def _load_receipt(
    path_value: str,
    *,
    expected_file_sha256: Optional[str] = None,
    adapter_path: Optional[Path] = None,
    entrypoint_path: Optional[Path] = None,
) -> Dict[str, Any]:
    path = _absolute_path(path_value)
    if path.is_symlink():
        raise FundingPaginationError("predecessor_receipt_symlink_rejected")
    raw, receipt = _load_json(path, "predecessor_receipt_unreadable")
    file_sha256 = _sha256_bytes(raw)
    if expected_file_sha256 is not None and file_sha256 != expected_file_sha256:
        raise FundingPaginationError("predecessor_receipt_hash_mismatch")
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise FundingPaginationError("predecessor_receipt_invalid")
    request = _verify_request(receipt)
    raw_path, raw_sha256, raw_bytes = _verify_raw(receipt)
    auth = receipt.get("authorization")
    source = receipt.get("source")
    structure = receipt.get("structure")
    if not isinstance(auth, dict) or not isinstance(source, dict) or not isinstance(structure, dict):
        raise FundingPaginationError("predecessor_receipt_sections_missing")
    if source.get("endpoint") != ENDPOINT or source.get("method") != "POST":
        raise FundingPaginationError("predecessor_source_binding_mismatch")
    if auth.get("consumed_before_http") is not True:
        raise FundingPaginationError("predecessor_authorization_not_consumed")
    if auth.get("source_contract_sha256") is None or not _is_sha256(
        auth.get("source_contract_sha256")
    ):
        raise FundingPaginationError("predecessor_source_contract_missing")
    if receipt.get("transport", {}).get("automatic_retries") != 0:
        raise FundingPaginationError("predecessor_retry_policy_invalid")
    if receipt.get("claim_boundary", {}).get("completeness_proven") is not False:
        raise FundingPaginationError("predecessor_completeness_claim_invalid")
    row_count = structure.get("row_count")
    if isinstance(row_count, bool) or not isinstance(row_count, int) or row_count < 0:
        raise FundingPaginationError("predecessor_row_count_invalid")
    min_time = structure.get("min_event_time")
    max_time = structure.get("max_event_time")
    if row_count:
        if not isinstance(min_time, int) or not isinstance(max_time, int):
            raise FundingPaginationError("predecessor_time_bounds_missing")
        if min_time > max_time:
            raise FundingPaginationError("predecessor_time_bounds_invalid")
    elif min_time is not None or max_time is not None:
        raise FundingPaginationError("empty_predecessor_time_bounds_invalid")
    min_boundary_hash, max_boundary_hash = _boundary_hashes(
        raw_path,
        coin=request["coin"],
        min_time=min_time,
        max_time=max_time,
    )
    for key, computed in (
        ("min_boundary_row_set_sha256", min_boundary_hash),
        ("max_boundary_row_set_sha256", max_boundary_hash),
        ("start_boundary_row_set_sha256", min_boundary_hash),
        ("boundary_row_set_sha256", max_boundary_hash),
    ):
        recorded = structure.get(key)
        if recorded is not None and recorded != computed:
            raise FundingPaginationError(f"{key}_mismatch")
    expected_adapter = _sha256_file(adapter_path) if adapter_path else None
    expected_entrypoint = _sha256_file(entrypoint_path) if entrypoint_path else None
    recorded_adapter = auth.get("adapter_sha256")
    recorded_entrypoint = auth.get("entrypoint_sha256")
    if recorded_adapter is not None and recorded_adapter != expected_adapter:
        raise FundingPaginationError("predecessor_adapter_hash_mismatch")
    if recorded_entrypoint is not None and recorded_entrypoint != expected_entrypoint:
        raise FundingPaginationError("predecessor_entrypoint_hash_mismatch")
    code_binding_status = (
        "EXACT_RECEIPT_BOUND"
        if recorded_adapter is not None and recorded_entrypoint is not None
        else "LEGACY_RECEIPT_CODE_HASHES_NOT_RECORDED_REVIEW_REQUIRED"
    )
    return {
        "path": str(path),
        "file_sha256": file_sha256,
        "canonical_receipt_sha256": _sha256_bytes(_canonical_bytes(receipt)),
        "raw_path": str(raw_path),
        "raw_sha256": raw_sha256,
        "raw_bytes": raw_bytes,
        "request": request,
        "source_contract_sha256": auth["source_contract_sha256"],
        "adapter_sha256": expected_adapter,
        "entrypoint_sha256": expected_entrypoint,
        "code_binding_status": code_binding_status,
        "row_count": row_count,
        "min_event_time": min_time,
        "max_event_time": max_time,
        "min_boundary_row_set_sha256": min_boundary_hash,
        "max_boundary_row_set_sha256": max_boundary_hash,
        "start_boundary_row_set_sha256": min_boundary_hash,
        "boundary_row_set_sha256": max_boundary_hash,
        "revision_number": auth.get("revision_number"),
    }


def _stop_decision(
    predecessor: Dict[str, Any],
    *,
    reason: str,
    limits: Dict[str, int],
    adapter_sha256: str,
    entrypoint_sha256: str,
) -> Dict[str, Any]:
    return {
        "schema_version": INTENT_SCHEMA,
        "status": reason,
        "network_fetch": False,
        "authorization_created": False,
        "predecessor": {
            "receipt_path": predecessor["path"],
            "receipt_file_sha256": predecessor["file_sha256"],
            "canonical_receipt_sha256": predecessor["canonical_receipt_sha256"],
            "raw_sha256": predecessor["raw_sha256"],
            "request_sha256": predecessor["request"]["sha256"],
            "source_contract_sha256": predecessor["source_contract_sha256"],
            "adapter_sha256": adapter_sha256,
            "entrypoint_sha256": entrypoint_sha256,
            "code_binding_status": predecessor["code_binding_status"],
            "max_boundary_row_set_sha256": predecessor["max_boundary_row_set_sha256"],
        },
        "limits": limits,
        "claim_boundary": {
            "completeness_status": UNKNOWN_STATUS,
            "completeness_proven": False,
            "source_semantics_ready": False,
            "causal_research_ready": False,
            "authorities": {key: False for key in AUTHORITY_KEYS},
        },
    }


def build_next_page_intent(
    *,
    predecessor_receipt_path: str,
    predecessor_receipt_sha256: str,
    sealed_start_time_ms: int,
    sealed_end_exclusive_ms: int,
    adapter_path: Path,
    entrypoint_path: Path,
    predecessor_page_number: int = 1,
    max_pages: int = 128,
    max_rows: int = 100_000,
    max_bytes: int = 64 * 1024 * 1024,
) -> Dict[str, Any]:
    """Build a next-page decision without network or authorization creation."""
    if not _is_sha256(predecessor_receipt_sha256):
        raise FundingPaginationError("predecessor_receipt_sha256_invalid")
    if (
        isinstance(sealed_start_time_ms, bool)
        or not isinstance(sealed_start_time_ms, int)
        or isinstance(sealed_end_exclusive_ms, bool)
        or not isinstance(sealed_end_exclusive_ms, int)
        or sealed_start_time_ms < 0
        or sealed_start_time_ms >= sealed_end_exclusive_ms
    ):
        raise FundingPaginationError("sealed_window_invalid")
    limits = {
        "max_pages": _positive_int(max_pages, "max_pages"),
        "max_rows": _positive_int(max_rows, "max_rows"),
        "max_bytes": _positive_int(max_bytes, "max_bytes"),
    }
    predecessor_page_number = _positive_int(
        predecessor_page_number, "predecessor_page_number"
    )
    predecessor = _load_receipt(
        predecessor_receipt_path,
        expected_file_sha256=predecessor_receipt_sha256,
        adapter_path=adapter_path,
        entrypoint_path=entrypoint_path,
    )
    adapter_sha256 = predecessor["adapter_sha256"]
    entrypoint_sha256 = predecessor["entrypoint_sha256"]
    request = predecessor["request"]
    if request["coin"] != request["payload"].get("coin"):
        raise FundingPaginationError("predecessor_coin_binding_mismatch")
    if request["coin"] is None or request["coin"] == "":
        raise FundingPaginationError("predecessor_coin_missing")
    if request["start_time_ms"] != request["payload"].get("startTime"):
        raise FundingPaginationError("predecessor_start_binding_mismatch")
    if request["end_time_exclusive_ms"] != sealed_end_exclusive_ms:
        raise FundingPaginationError("sealed_end_binding_mismatch")
    if request["wire_end_inclusive_ms"] != sealed_end_exclusive_ms - 1:
        raise FundingPaginationError("wire_end_binding_mismatch")
    if request["start_time_ms"] < sealed_start_time_ms:
        raise FundingPaginationError("predecessor_before_sealed_start")
    if request["start_time_ms"] >= sealed_end_exclusive_ms:
        raise FundingPaginationError("predecessor_start_outside_sealed_window")
    if predecessor["row_count"] == 0:
        return _stop_decision(
            predecessor,
            reason="STOP_EMPTY_PAGE_REVIEW_REQUIRED",
            limits=limits,
            adapter_sha256=adapter_sha256,
            entrypoint_sha256=entrypoint_sha256,
        )
    if predecessor["row_count"] > limits["max_rows"]:
        return _stop_decision(
            predecessor,
            reason="STOP_MAX_ROWS_REVIEW_REQUIRED",
            limits=limits,
            adapter_sha256=adapter_sha256,
            entrypoint_sha256=entrypoint_sha256,
        )
    if predecessor["raw_bytes"] > limits["max_bytes"]:
        return _stop_decision(
            predecessor,
            reason="STOP_MAX_BYTES_REVIEW_REQUIRED",
            limits=limits,
            adapter_sha256=adapter_sha256,
            entrypoint_sha256=entrypoint_sha256,
        )
    page_number = predecessor_page_number
    if page_number >= limits["max_pages"]:
        return _stop_decision(
            predecessor,
            reason="STOP_MAX_PAGES_REVIEW_REQUIRED",
            limits=limits,
            adapter_sha256=adapter_sha256,
            entrypoint_sha256=entrypoint_sha256,
        )
    next_start = predecessor["max_event_time"]
    if not isinstance(next_start, int) or next_start <= request["start_time_ms"]:
        return _stop_decision(
            predecessor,
            reason="STOP_NO_PROGRESS_REVIEW_REQUIRED",
            limits=limits,
            adapter_sha256=adapter_sha256,
            entrypoint_sha256=entrypoint_sha256,
        )
    if next_start >= sealed_end_exclusive_ms:
        return _stop_decision(
            predecessor,
            reason="STOP_SEALED_END_REACHED_REVIEW_REQUIRED",
            limits=limits,
            adapter_sha256=adapter_sha256,
            entrypoint_sha256=entrypoint_sha256,
        )
    payload = {
        "coin": request["coin"],
        "endTime": sealed_end_exclusive_ms - 1,
        "startTime": next_start,
        "type": "fundingHistory",
    }
    request_sha256 = _sha256_bytes(_canonical_bytes(payload))
    return {
        "schema_version": INTENT_SCHEMA,
        "status": "NEXT_PAGE_INTENT_OFFLINE_REVIEW_REQUIRED",
        "network_fetch": False,
        "authorization_created": False,
        "page": {
            "page_number": page_number + 1,
            "predecessor_page_number": page_number,
            "next_start_policy": NEXT_START_POLICY,
            "same_timestamp_identity": "UNKNOWN_REVIEW_REQUIRED",
            "boundary_identity": {
                "timestamp_ms": predecessor["max_event_time"],
                "predecessor_row_set_sha256": predecessor["max_boundary_row_set_sha256"],
                "next_page_must_match_exactly": True,
            },
        },
        "request": {
            "payload": payload,
            "sha256": request_sha256,
            "coin": request["coin"],
            "start_time_ms": next_start,
            "end_time_exclusive_ms": sealed_end_exclusive_ms,
            "wire_end_inclusive_ms": sealed_end_exclusive_ms - 1,
            "boundary_policy": "source-inclusive/local-exclusive",
        },
        "predecessor": {
            "receipt_path": predecessor["path"],
            "receipt_file_sha256": predecessor["file_sha256"],
            "canonical_receipt_sha256": predecessor["canonical_receipt_sha256"],
            "raw_sha256": predecessor["raw_sha256"],
            "request_sha256": request["sha256"],
            "source_contract_sha256": predecessor["source_contract_sha256"],
            "adapter_sha256": adapter_sha256,
            "entrypoint_sha256": entrypoint_sha256,
            "code_binding_status": predecessor["code_binding_status"],
        },
        "observed": {
            "row_count": predecessor["row_count"],
            "raw_bytes": predecessor["raw_bytes"],
            "min_event_time": predecessor["min_event_time"],
            "max_event_time": predecessor["max_event_time"],
            "max_boundary_row_set_sha256": predecessor["max_boundary_row_set_sha256"],
        },
        "limits": limits,
        "claim_boundary": {
            "completeness_status": UNKNOWN_STATUS,
            "completeness_proven": False,
            "source_semantics_ready": False,
            "causal_research_ready": False,
            "authorities": {key: False for key in AUTHORITY_KEYS},
        },
    }


def write_next_page_intent(intent: Dict[str, Any], output_root: str) -> Dict[str, Any]:
    """Write one intent into a new O_EXCL page namespace."""
    if intent.get("schema_version") != INTENT_SCHEMA:
        raise FundingPaginationError("intent_schema_invalid")
    root = _absolute_path(output_root)
    if root.exists() and root.is_symlink():
        raise FundingPaginationError("output_root_symlink_rejected")
    root.mkdir(parents=True, exist_ok=True)
    page = intent.get("page") or {}
    number = page.get("page_number", 1)
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise FundingPaginationError("intent_page_number_invalid")
    page_dir = root / f"page-{number:04d}"
    try:
        page_dir.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise FundingPaginationError("page_namespace_exists_no_blind_retry") from exc
    intent_path = page_dir / "intent.json"
    _exclusive_publish(intent_path, _canonical_bytes(intent) + b"\n")
    result = dict(intent)
    result["intent_path"] = str(intent_path)
    return result


def assemble_pagination(
    *,
    page_receipt_paths: Sequence[str],
    output_path: str,
    sealed_start_time_ms: int,
    sealed_end_exclusive_ms: int,
    adapter_path: Path,
    entrypoint_path: Path,
    max_pages: int = 128,
    max_rows: int = 100_000,
    max_bytes: int = 64 * 1024 * 1024,
) -> Dict[str, Any]:
    """Assemble page metadata only; raw pages are never merged or deduped."""
    if not page_receipt_paths:
        raise FundingPaginationError("page_receipts_required")
    limits = {
        "max_pages": _positive_int(max_pages, "max_pages"),
        "max_rows": _positive_int(max_rows, "max_rows"),
        "max_bytes": _positive_int(max_bytes, "max_bytes"),
    }
    if len(page_receipt_paths) > limits["max_pages"]:
        raise FundingPaginationError("max_pages_exceeded")
    pages: List[Dict[str, Any]] = []
    seen_paths = set()
    previous: Optional[Dict[str, Any]] = None
    seen_request_hashes = set()
    total_rows = 0
    total_bytes = 0
    for index, receipt_path in enumerate(page_receipt_paths, start=1):
        page = _load_receipt(receipt_path, adapter_path=adapter_path, entrypoint_path=entrypoint_path)
        request = page["request"]
        if request["sha256"] in seen_request_hashes:
            raise FundingPaginationError("pagination_cycle_request")
        seen_request_hashes.add(request["sha256"])
        if page["path"] in seen_paths:
            raise FundingPaginationError("pagination_cycle_receipt_path")
        seen_paths.add(page["path"])
        if request["end_time_exclusive_ms"] != sealed_end_exclusive_ms:
            raise FundingPaginationError("sealed_end_binding_mismatch")
        if request["wire_end_inclusive_ms"] != sealed_end_exclusive_ms - 1:
            raise FundingPaginationError("wire_end_binding_mismatch")
        if request["coin"] != request["payload"].get("coin"):
            raise FundingPaginationError("coin_binding_mismatch")
        if index == 1:
            if request["start_time_ms"] != sealed_start_time_ms:
                raise FundingPaginationError("first_page_start_mismatch")
        else:
            assert previous is not None
            if page["source_contract_sha256"] != previous["source_contract_sha256"]:
                raise FundingPaginationError("source_contract_changed")
            if request["sha256"] == previous["request"]["sha256"]:
                raise FundingPaginationError("pagination_cycle_request")
            if request["start_time_ms"] != previous["max_event_time"]:
                raise FundingPaginationError("BOUNDARY_IDENTITY_AMBIGUOUS")
            if page["row_count"]:
                if page["min_boundary_row_set_sha256"] != previous["max_boundary_row_set_sha256"]:
                    raise FundingPaginationError("BOUNDARY_IDENTITY_AMBIGUOUS")
                if page["max_event_time"] <= previous["max_event_time"]:
                    raise FundingPaginationError("NO_PROGRESS")
        if page["row_count"]:
            if page["max_event_time"] <= request["start_time_ms"]:
                raise FundingPaginationError("page_no_progress")
        elif index != len(page_receipt_paths):
            raise FundingPaginationError("empty_page_must_be_terminal")
        total_rows += page["row_count"]
        total_bytes += page["raw_bytes"]
        if total_rows > limits["max_rows"]:
            raise FundingPaginationError("max_rows_exceeded")
        if total_bytes > limits["max_bytes"]:
            raise FundingPaginationError("max_bytes_exceeded")
        pages.append(
            {
                "page_number": index,
                "receipt_path": page["path"],
                "receipt_file_sha256": page["file_sha256"],
                "canonical_receipt_sha256": page["canonical_receipt_sha256"],
                "raw_sha256": page["raw_sha256"],
                "request_sha256": request["sha256"],
                "row_count": page["row_count"],
                "raw_bytes": page["raw_bytes"],
                "min_event_time": page["min_event_time"],
                "max_event_time": page["max_event_time"],
                "min_boundary_row_set_sha256": page["min_boundary_row_set_sha256"],
                "max_boundary_row_set_sha256": page["max_boundary_row_set_sha256"],
                "start_boundary_row_set_sha256": page["start_boundary_row_set_sha256"],
                "boundary_row_set_sha256": page["boundary_row_set_sha256"],
                "source_contract_sha256": page["source_contract_sha256"],
            }
        )
        previous = page
    output = {
        "schema_version": CONTROLLER_SCHEMA,
        "status": "PAGINATION_ASSEMBLY_UNKNOWN_REVIEW_REQUIRED",
        "network_fetch": False,
        "raw_pages_merged": False,
        "deduplicated": False,
        "pages": pages,
        "aggregate": {
            "page_count": len(pages),
            "row_count": total_rows,
            "raw_bytes": total_bytes,
            "min_event_time": pages[0]["min_event_time"],
            "max_event_time": pages[-1]["max_event_time"],
            "duplicate_count": None,
            "gap_count": None,
            "conflict_count": None,
            "completeness_status": UNKNOWN_STATUS,
        },
        "source_binding": {
            "endpoint": ENDPOINT,
            "query_type": "fundingHistory",
            "adapter_sha256": _sha256_file(adapter_path),
            "entrypoint_sha256": _sha256_file(entrypoint_path),
            "source_contract_sha256": pages[0]["source_contract_sha256"],
        },
        "claim_boundary": {
            "completeness_proven": False,
            "source_semantics_ready": False,
            "causal_research_ready": False,
            "strategy_authorized": False,
            "trading_authorized": False,
            "authorities": {key: False for key in AUTHORITY_KEYS},
        },
        "limits": limits,
    }
    destination = _absolute_path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _exclusive_publish(destination, _canonical_bytes(output) + b"\n")
    output["output_path"] = str(destination)
    return output
