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
import stat
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
TERMINAL_STATUSES = frozenset(
    {
        "RAW_CAPTURED_EMPTY_RESPONSE_COMPLETENESS_UNKNOWN_REVIEW_REQUIRED",
        "RAW_CAPTURED_STRUCTURE_VALID_COMPLETENESS_UNKNOWN_REVIEW_REQUIRED",
        "RAW_CAPTURED_JSON_INVALID",
        "RAW_CAPTURED_STRUCTURE_INVALID",
    }
)
ACQUISITION_KINDS = frozenset(
    {"OFFLINE_RECOVERY", "SOURCE_ACQUISITION", "SOURCE_REOBSERVATION"}
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


def _read_regular_nofollow(path: Path, error: str) -> bytes:
    """Read one regular-file inode through one O_NOFOLLOW descriptor."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise FundingPaginationError(f"{error}_nofollow_unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise FundingPaginationError(error) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise FundingPaginationError(f"{error}_not_regular")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            after.st_size != len(data)
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise FundingPaginationError(f"{error}_changed_while_reading")
        return data
    except FundingPaginationError:
        raise
    except OSError as exc:
        raise FundingPaginationError(error) from exc
    finally:
        os.close(descriptor)


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(_read_regular_nofollow(path, f"file_unreadable:{path}"))


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


def _nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FundingPaginationError(f"{name}_must_be_nonnegative_integer")
    return value


def _cumulative(page_count: int, row_count: int, raw_bytes: int) -> Dict[str, int]:
    return {
        "page_count": page_count,
        "row_count": row_count,
        "raw_bytes": raw_bytes,
    }


def _add_page(cumulative: Dict[str, int], page: Dict[str, Any]) -> Dict[str, int]:
    return _cumulative(
        cumulative["page_count"] + 1,
        cumulative["row_count"] + page["row_count"],
        cumulative["raw_bytes"] + page["raw_bytes"],
    )


def _load_json(path: Path, error: str) -> tuple[bytes, Dict[str, Any]]:
    try:
        raw = _read_regular_nofollow(path, error)
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FundingPaginationError(error) from exc
    if not isinstance(value, dict):
        raise FundingPaginationError(error)
    return raw, value


def _verify_raw(receipt: Dict[str, Any]) -> tuple[Path, str, bytes, int]:
    raw_info = receipt.get("raw")
    if not isinstance(raw_info, dict) or not _is_sha256(raw_info.get("sha256")):
        raise FundingPaginationError("predecessor_raw_integrity_missing")
    raw_path = _absolute_path(raw_info.get("path"))
    raw_bytes = _read_regular_nofollow(raw_path, "predecessor_raw_unreadable")
    raw_sha256 = _sha256_bytes(raw_bytes)
    if raw_sha256 != raw_info["sha256"]:
        raise FundingPaginationError("predecessor_raw_integrity_mismatch")
    return raw_path, raw_sha256, raw_bytes, len(raw_bytes)


def _row_set_hash(rows: Iterable[Dict[str, Any]]) -> str:
    canonical_rows = sorted(_canonical_bytes(row) for row in rows)
    return _sha256_bytes(b"[" + b",".join(canonical_rows) + b"]")


def _boundary_hashes(
    raw_bytes: bytes,
    *,
    coin: str,
    row_count: int,
    min_time: Optional[int],
    max_time: Optional[int],
) -> tuple[Optional[str], Optional[str]]:
    try:
        payload = json.loads(raw_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
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
    if len(rows) != row_count:
        raise FundingPaginationError("predecessor_row_count_mismatch")
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
    raw, receipt = _load_json(path, "predecessor_receipt_unreadable")
    file_sha256 = _sha256_bytes(raw)
    if expected_file_sha256 is not None and file_sha256 != expected_file_sha256:
        raise FundingPaginationError("predecessor_receipt_hash_mismatch")
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise FundingPaginationError("predecessor_receipt_invalid")
    request = _verify_request(receipt)
    raw_path, raw_sha256, raw_payload_bytes, raw_bytes = _verify_raw(receipt)
    auth = receipt.get("authorization")
    source = receipt.get("source")
    structure = receipt.get("structure")
    if not isinstance(auth, dict) or not isinstance(source, dict) or not isinstance(structure, dict):
        raise FundingPaginationError("predecessor_receipt_sections_missing")
    if (
        source.get("endpoint") != ENDPOINT
        or source.get("method") != "POST"
        or source.get("query_type") != "fundingHistory"
    ):
        raise FundingPaginationError("predecessor_source_binding_mismatch")
    if receipt.get("status") not in TERMINAL_STATUSES:
        raise FundingPaginationError("predecessor_terminal_status_invalid")
    if auth.get("consumed_before_http") is not True:
        raise FundingPaginationError("predecessor_authorization_not_consumed")
    if auth.get("source_contract_sha256") is None or not _is_sha256(
        auth.get("source_contract_sha256")
    ):
        raise FundingPaginationError("predecessor_source_contract_missing")
    acquisition_kind = auth.get("acquisition_kind")
    if acquisition_kind not in ACQUISITION_KINDS:
        raise FundingPaginationError("predecessor_acquisition_kind_invalid")
    transport = receipt.get("transport")
    if not isinstance(transport, dict):
        raise FundingPaginationError("predecessor_transport_missing")
    if transport.get("automatic_retries") != 0:
        raise FundingPaginationError("predecessor_retry_policy_invalid")
    if transport.get("http_requests") != (
        0 if acquisition_kind == "OFFLINE_RECOVERY" else 1
    ):
        raise FundingPaginationError("predecessor_http_request_count_invalid")
    if transport.get("redirects_allowed") is not False:
        raise FundingPaginationError("predecessor_redirect_policy_invalid")
    claim_boundary = receipt.get("claim_boundary")
    if not isinstance(claim_boundary, dict):
        raise FundingPaginationError("predecessor_claim_boundary_missing")
    for key in (
        "raw_acquired",
        "completeness_proven",
        "source_semantics_ready",
        "causal_research_ready",
        "strategy_authorized",
        "trading_authorized",
        "promotable",
        "downstream_allowed",
    ):
        expected = True if key == "raw_acquired" else False
        if claim_boundary.get(key) is not expected:
            raise FundingPaginationError(f"predecessor_claim_boundary_invalid:{key}")
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
    if structure.get("gap_count") is not None:
        raise FundingPaginationError("predecessor_gap_count_must_remain_unknown")
    if structure.get("completeness_status") != UNKNOWN_STATUS:
        raise FundingPaginationError("predecessor_completeness_status_invalid")
    min_boundary_hash, max_boundary_hash = _boundary_hashes(
        raw_payload_bytes,
        coin=request["coin"],
        row_count=row_count,
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


def _load_intent_lineage(
    path_value: str,
    expected_file_sha256: str,
    *,
    sealed_start_time_ms: int,
    sealed_end_exclusive_ms: int,
    adapter_path: Path,
    entrypoint_path: Path,
    max_pages: int,
    seen_paths: Optional[set[str]] = None,
) -> Dict[str, Any]:
    """Load and anchor an intent chain at the immutable first-page receipt."""
    if not _is_sha256(expected_file_sha256):
        raise FundingPaginationError("predecessor_intent_sha256_invalid")
    path = _absolute_path(path_value)
    raw, intent = _load_json(path, "predecessor_intent_unreadable")
    actual_sha256 = _sha256_bytes(raw)
    if actual_sha256 != expected_file_sha256:
        raise FundingPaginationError("predecessor_intent_hash_mismatch")
    seen = seen_paths if seen_paths is not None else set()
    if str(path) in seen:
        raise FundingPaginationError("pagination_lineage_cycle")
    seen.add(str(path))
    try:
        if intent.get("schema_version") != INTENT_SCHEMA:
            raise FundingPaginationError("predecessor_intent_schema_invalid")
        page = intent.get("page")
        request_info = intent.get("request")
        lineage = intent.get("lineage")
        predecessor_binding = intent.get("predecessor")
        if not isinstance(page, dict) or not isinstance(request_info, dict):
            raise FundingPaginationError("predecessor_intent_sections_missing")
        if not isinstance(lineage, dict) or not isinstance(predecessor_binding, dict):
            raise FundingPaginationError("predecessor_intent_lineage_missing")
        page_number = _positive_int(page.get("page_number"), "intent_page_number")
        predecessor_page_number = _positive_int(
            page.get("predecessor_page_number"), "intent_predecessor_page_number"
        )
        if page_number != predecessor_page_number + 1 or page_number > max_pages:
            raise FundingPaginationError("pagination_lineage_page_number_invalid")
        payload = request_info.get("payload")
        if not isinstance(payload, dict):
            raise FundingPaginationError("predecessor_intent_request_missing")
        if set(payload) != {"coin", "endTime", "startTime", "type"}:
            raise FundingPaginationError("predecessor_intent_request_shape_invalid")
        if payload.get("type") != "fundingHistory":
            raise FundingPaginationError("predecessor_intent_request_type_invalid")
        request_sha256 = request_info.get("sha256")
        if not _is_sha256(request_sha256) or request_sha256 != _sha256_bytes(
            _canonical_bytes(payload)
        ):
            raise FundingPaginationError("predecessor_intent_request_hash_invalid")
        if request_info.get("coin") != payload.get("coin"):
            raise FundingPaginationError("predecessor_intent_coin_binding_mismatch")
        if request_info.get("start_time_ms") != payload.get("startTime"):
            raise FundingPaginationError("predecessor_intent_start_binding_mismatch")
        if request_info.get("boundary_policy") != "source-inclusive/local-exclusive":
            raise FundingPaginationError("predecessor_intent_boundary_policy_invalid")
        if request_info.get("end_time_exclusive_ms") != sealed_end_exclusive_ms:
            raise FundingPaginationError("predecessor_intent_sealed_end_mismatch")
        if request_info.get("wire_end_inclusive_ms") != sealed_end_exclusive_ms - 1:
            raise FundingPaginationError("predecessor_intent_wire_end_mismatch")
        predecessor_path = predecessor_binding.get("receipt_path")
        predecessor_file_sha256 = predecessor_binding.get("receipt_file_sha256")
        if not isinstance(predecessor_path, str) or not _is_sha256(
            predecessor_file_sha256
        ):
            raise FundingPaginationError("predecessor_intent_receipt_binding_missing")
        bound_receipt = _load_receipt(
            predecessor_path,
            expected_file_sha256=predecessor_file_sha256,
            adapter_path=adapter_path,
            entrypoint_path=entrypoint_path,
        )
        if payload.get("startTime") != bound_receipt["max_event_time"]:
            raise FundingPaginationError("pagination_lineage_cursor_mismatch")
        if request_info.get("start_time_ms") != bound_receipt["max_event_time"]:
            raise FundingPaginationError("pagination_lineage_cursor_mismatch")
        if payload.get("endTime") != sealed_end_exclusive_ms - 1:
            raise FundingPaginationError("pagination_lineage_wire_end_mismatch")
        expected_bindings = {
            "receipt_file_sha256": bound_receipt["file_sha256"],
            "canonical_receipt_sha256": bound_receipt["canonical_receipt_sha256"],
            "raw_sha256": bound_receipt["raw_sha256"],
            "request_sha256": bound_receipt["request"]["sha256"],
            "source_contract_sha256": bound_receipt["source_contract_sha256"],
            "adapter_sha256": bound_receipt["adapter_sha256"],
            "entrypoint_sha256": bound_receipt["entrypoint_sha256"],
            "code_binding_status": bound_receipt["code_binding_status"],
            "max_boundary_row_set_sha256": bound_receipt[
                "max_boundary_row_set_sha256"
            ],
        }
        for key, expected in expected_bindings.items():
            if predecessor_binding.get(key) != expected:
                raise FundingPaginationError(
                    f"pagination_lineage_predecessor_binding_mismatch:{key}"
                )
        identity = page.get("boundary_identity")
        if not isinstance(identity, dict):
            raise FundingPaginationError("predecessor_intent_boundary_missing")
        if identity.get("timestamp_ms") != bound_receipt["max_event_time"]:
            raise FundingPaginationError("pagination_lineage_boundary_mismatch")
        if identity.get("predecessor_row_set_sha256") != bound_receipt[
            "max_boundary_row_set_sha256"
        ]:
            raise FundingPaginationError("pagination_lineage_boundary_mismatch")
        if identity.get("next_page_must_match_exactly") is not True:
            raise FundingPaginationError("pagination_lineage_boundary_policy_invalid")
        current_page_number = _positive_int(
            lineage.get("current_page_number"), "lineage_current_page_number"
        )
        next_page_number = _positive_int(
            lineage.get("next_page_number"), "lineage_next_page_number"
        )
        if (
            current_page_number != predecessor_page_number
            or next_page_number != page_number
        ):
            raise FundingPaginationError("pagination_lineage_page_relation_invalid")
        cumulative_info = intent.get("cumulative")
        if not isinstance(cumulative_info, dict):
            raise FundingPaginationError("pagination_lineage_cumulative_missing")
        lineage_kind = lineage.get("kind")
        if lineage_kind == "FIXED_FIRST_PAGE":
            if current_page_number != 1:
                raise FundingPaginationError("pagination_lineage_first_page_invalid")
            if lineage.get("predecessor_intent_path") is not None or lineage.get(
                "predecessor_intent_sha256"
            ) is not None:
                raise FundingPaginationError("pagination_lineage_first_page_has_parent")
            if bound_receipt["request"]["start_time_ms"] != sealed_start_time_ms:
                raise FundingPaginationError("pagination_lineage_first_page_anchor_invalid")
            expected_cumulative = _cumulative(
                1, bound_receipt["row_count"], bound_receipt["raw_bytes"]
            )
        elif lineage_kind == "INTENT_BOUND":
            parent_path = lineage.get("predecessor_intent_path")
            parent_sha256 = lineage.get("predecessor_intent_sha256")
            if not isinstance(parent_path, str) or not _is_sha256(parent_sha256):
                raise FundingPaginationError("pagination_lineage_parent_missing")
            parent = _load_intent_lineage(
                parent_path,
                parent_sha256,
                sealed_start_time_ms=sealed_start_time_ms,
                sealed_end_exclusive_ms=sealed_end_exclusive_ms,
                adapter_path=adapter_path,
                entrypoint_path=entrypoint_path,
                max_pages=max_pages,
                seen_paths=seen,
            )
            if parent["page_number"] != current_page_number:
                raise FundingPaginationError("pagination_lineage_parent_page_mismatch")
            if parent["request_sha256"] != bound_receipt["request"]["sha256"]:
                raise FundingPaginationError("pagination_lineage_parent_request_mismatch")
            expected_cumulative = _add_page(parent["cumulative"], bound_receipt)
        else:
            raise FundingPaginationError("pagination_lineage_kind_invalid")
        actual_cumulative = {
            key: _nonnegative_int(cumulative_info.get(key), f"cumulative_{key}")
            for key in ("page_count", "row_count", "raw_bytes")
        }
        if actual_cumulative != expected_cumulative:
            raise FundingPaginationError("pagination_lineage_cumulative_mismatch")
        if actual_cumulative["page_count"] != predecessor_page_number:
            raise FundingPaginationError("pagination_lineage_cumulative_page_mismatch")
        return {
            "path": str(path),
            "file_sha256": actual_sha256,
            "page_number": page_number,
            "predecessor_page_number": predecessor_page_number,
            "request_sha256": request_sha256,
            "predecessor": bound_receipt,
            "cumulative": actual_cumulative,
        }
    finally:
        seen.discard(str(path))


def _stop_decision(
    predecessor: Dict[str, Any],
    *,
    reason: str,
    limits: Dict[str, int],
    adapter_sha256: str,
    entrypoint_sha256: str,
    current_page_number: int,
    lineage: Dict[str, Any],
    cumulative: Dict[str, int],
) -> Dict[str, Any]:
    return {
        "schema_version": INTENT_SCHEMA,
        "status": reason,
        "network_fetch": False,
        "authorization_created": False,
        "lineage": lineage,
        "cumulative": cumulative,
        "page": {"page_number": current_page_number},
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
    predecessor_intent_path: Optional[str] = None,
    predecessor_intent_sha256: Optional[str] = None,
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
    predecessor = _load_receipt(
        predecessor_receipt_path,
        expected_file_sha256=predecessor_receipt_sha256,
        adapter_path=adapter_path,
        entrypoint_path=entrypoint_path,
    )
    adapter_sha256 = predecessor["adapter_sha256"]
    entrypoint_sha256 = predecessor["entrypoint_sha256"]
    if (predecessor_intent_path is None) != (predecessor_intent_sha256 is None):
        raise FundingPaginationError("predecessor_intent_lineage_incomplete")
    if predecessor_intent_path is None:
        if predecessor["request"]["start_time_ms"] != sealed_start_time_ms:
            raise FundingPaginationError("missing_pagination_lineage")
        current_page_number = 1
        lineage = {
            "kind": "FIXED_FIRST_PAGE",
            "current_page_number": 1,
            "next_page_number": 2,
            "predecessor_intent_path": None,
            "predecessor_intent_sha256": None,
        }
        current_cumulative = _cumulative(
            1, predecessor["row_count"], predecessor["raw_bytes"]
        )
    else:
        intent_lineage = _load_intent_lineage(
            predecessor_intent_path,
            predecessor_intent_sha256,
            sealed_start_time_ms=sealed_start_time_ms,
            sealed_end_exclusive_ms=sealed_end_exclusive_ms,
            adapter_path=adapter_path,
            entrypoint_path=entrypoint_path,
            max_pages=limits["max_pages"],
        )
        if predecessor["request"]["sha256"] != intent_lineage["request_sha256"]:
            raise FundingPaginationError("pagination_lineage_current_request_mismatch")
        current_page_number = intent_lineage["page_number"]
        lineage = {
            "kind": "INTENT_BOUND",
            "current_page_number": current_page_number,
            "next_page_number": current_page_number + 1,
            "predecessor_intent_path": intent_lineage["path"],
            "predecessor_intent_sha256": intent_lineage["file_sha256"],
        }
        current_cumulative = _add_page(intent_lineage["cumulative"], predecessor)
    if current_cumulative["page_count"] != current_page_number:
        raise FundingPaginationError("pagination_lineage_current_page_mismatch")
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
            current_page_number=current_page_number,
            lineage=lineage,
            cumulative=current_cumulative,
        )
    if current_cumulative["row_count"] > limits["max_rows"]:
        return _stop_decision(
            predecessor,
            reason="STOP_MAX_ROWS_REVIEW_REQUIRED",
            limits=limits,
            adapter_sha256=adapter_sha256,
            entrypoint_sha256=entrypoint_sha256,
            current_page_number=current_page_number,
            lineage=lineage,
            cumulative=current_cumulative,
        )
    if current_cumulative["raw_bytes"] > limits["max_bytes"]:
        return _stop_decision(
            predecessor,
            reason="STOP_MAX_BYTES_REVIEW_REQUIRED",
            limits=limits,
            adapter_sha256=adapter_sha256,
            entrypoint_sha256=entrypoint_sha256,
            current_page_number=current_page_number,
            lineage=lineage,
            cumulative=current_cumulative,
        )
    if current_page_number >= limits["max_pages"]:
        return _stop_decision(
            predecessor,
            reason="STOP_MAX_PAGES_REVIEW_REQUIRED",
            limits=limits,
            adapter_sha256=adapter_sha256,
            entrypoint_sha256=entrypoint_sha256,
            current_page_number=current_page_number,
            lineage=lineage,
            cumulative=current_cumulative,
        )
    next_start = predecessor["max_event_time"]
    if not isinstance(next_start, int) or next_start <= request["start_time_ms"]:
        return _stop_decision(
            predecessor,
            reason="STOP_NO_PROGRESS_REVIEW_REQUIRED",
            limits=limits,
            adapter_sha256=adapter_sha256,
            entrypoint_sha256=entrypoint_sha256,
            current_page_number=current_page_number,
            lineage=lineage,
            cumulative=current_cumulative,
        )
    if next_start >= sealed_end_exclusive_ms:
        return _stop_decision(
            predecessor,
            reason="STOP_SEALED_END_REACHED_REVIEW_REQUIRED",
            limits=limits,
            adapter_sha256=adapter_sha256,
            entrypoint_sha256=entrypoint_sha256,
            current_page_number=current_page_number,
            lineage=lineage,
            cumulative=current_cumulative,
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
        "lineage": lineage,
        "cumulative": current_cumulative,
        "page": {
            "page_number": current_page_number + 1,
            "predecessor_page_number": current_page_number,
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
            "max_boundary_row_set_sha256": predecessor[
                "max_boundary_row_set_sha256"
            ],
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
    lineage = intent.get("lineage")
    if not isinstance(lineage, dict) or lineage.get("next_page_number") != number:
        raise FundingPaginationError("intent_lineage_page_number_invalid")
    page_dir = root / f"page-{number:04d}"
    try:
        page_dir.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise FundingPaginationError("page_namespace_exists_no_blind_retry") from exc
    intent_path = page_dir / "intent.json"
    intent_bytes = _canonical_bytes(intent) + b"\n"
    _exclusive_publish(intent_path, intent_bytes)
    result = dict(intent)
    result["intent_path"] = str(intent_path)
    result["intent_file_sha256"] = _sha256_bytes(intent_bytes)
    return result


def assemble_pagination(
    *,
    page_receipt_bindings: Sequence[Dict[str, str]],
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
    if not page_receipt_bindings:
        raise FundingPaginationError("page_receipts_required")
    limits = {
        "max_pages": _positive_int(max_pages, "max_pages"),
        "max_rows": _positive_int(max_rows, "max_rows"),
        "max_bytes": _positive_int(max_bytes, "max_bytes"),
    }
    if len(page_receipt_bindings) > limits["max_pages"]:
        raise FundingPaginationError("max_pages_exceeded")
    pages: List[Dict[str, Any]] = []
    seen_paths = set()
    previous: Optional[Dict[str, Any]] = None
    seen_request_hashes = set()
    total_rows = 0
    total_bytes = 0
    cumulative_page_count = 0
    legacy_code_binding_seen = False
    for index, binding in enumerate(page_receipt_bindings, start=1):
        if not isinstance(binding, dict):
            raise FundingPaginationError("page_receipt_binding_sha_required")
        receipt_path = binding.get("path")
        expected_file_sha256 = binding.get("file_sha256")
        if not isinstance(receipt_path, str) or not _is_sha256(expected_file_sha256):
            raise FundingPaginationError("page_receipt_binding_sha_required")
        page = _load_receipt(
            receipt_path,
            expected_file_sha256=expected_file_sha256,
            adapter_path=adapter_path,
            entrypoint_path=entrypoint_path,
        )
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
        elif index != len(page_receipt_bindings):
            raise FundingPaginationError("empty_page_must_be_terminal")
        total_rows += page["row_count"]
        total_bytes += page["raw_bytes"]
        cumulative_page_count += 1
        if page["code_binding_status"] != "EXACT_RECEIPT_BOUND":
            legacy_code_binding_seen = True
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
                "code_binding_status": page["code_binding_status"],
                "cumulative": _cumulative(
                    cumulative_page_count, total_rows, total_bytes
                ),
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
            "cumulative": _cumulative(cumulative_page_count, total_rows, total_bytes),
        },
        "source_binding": {
            "endpoint": ENDPOINT,
            "query_type": "fundingHistory",
            "adapter_sha256": _sha256_file(adapter_path),
            "entrypoint_sha256": _sha256_file(entrypoint_path),
            "source_contract_sha256": pages[0]["source_contract_sha256"],
            "code_binding_status": (
                "LEGACY_RECEIPT_CODE_HASHES_NOT_RECORDED_REVIEW_REQUIRED"
                if legacy_code_binding_seen
                else "EXACT_RECEIPT_BOUND"
            ),
        },
        "claim_boundary": {
            "completeness_proven": False,
            "source_semantics_ready": False,
            "causal_research_ready": False,
            "strategy_authorized": False,
            "trading_authorized": False,
            "structural_readiness": (
                "LEGACY_REVIEW_REQUIRED_NO_DOWNSTREAM_PROMOTION"
                if legacy_code_binding_seen
                else "REVIEW_REQUIRED"
            ),
            "authorities": {key: False for key in AUTHORITY_KEYS},
        },
        "limits": limits,
    }
    destination = _absolute_path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _exclusive_publish(destination, _canonical_bytes(output) + b"\n")
    output["output_path"] = str(destination)
    return output
