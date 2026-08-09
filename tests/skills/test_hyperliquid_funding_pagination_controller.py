from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest


SKILL_ROOT = (
    Path(__file__).resolve().parents[2]
    / "optional-skills"
    / "blockchain"
    / "hyperliquid"
)
ADAPTER_PATH = SKILL_ROOT / "scripts" / "funding_contract_adapter.py"
ENTRYPOINT_PATH = SKILL_ROOT / "scripts" / "hyperliquid_client.py"
CONTROLLER_PATH = SKILL_ROOT / "scripts" / "funding_pagination_controller.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def canonical_bytes(payload) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class FakeResponse:
    status = 200

    def __init__(self, body: bytes):
        self.body = body
        self.headers = {"Content-Type": "application/json", "Content-Encoding": ""}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def getcode(self):
        return self.status

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


def write_authorization(mod, root: Path, *, request: dict, output: Path):
    root.mkdir(parents=True, exist_ok=True)
    marker = root / "consumed.json"
    payload = {
        "schema_version": mod.AUTHORIZATION_SCHEMA,
        "authorization_id": f"owner-test-{output.name}",
        "command": mod.COMMAND,
        "endpoint": mod.ENDPOINT,
        "source_contract_sha256": "a" * 64,
        "request_sha256": sha256_bytes(canonical_bytes(request)),
        "local_end_exclusive_ms": request["endTime"] + 1,
        "wire_end_inclusive_ms": request["endTime"],
        "coin": request["coin"],
        "start_time_ms": request["startTime"],
        "end_time_ms": request["endTime"] + 1,
        "output_dir": str(output),
        "consumption_marker_path": str(marker),
        "maximum_http_requests": 1,
        "adapter_sha256": sha256_bytes(ADAPTER_PATH.read_bytes()),
        "entrypoint_sha256": sha256_bytes(ENTRYPOINT_PATH.read_bytes()),
        "network_fetch": True,
        "revision_number": 1,
        "predecessor_receipt_path": None,
        "predecessor_receipt_sha256": None,
        "authorities": {key: False for key in mod.AUTHORITY_KEYS},
    }
    path = root / f"authorization-{output.name}.json"
    raw = canonical_bytes(payload) + b"\n"
    path.write_bytes(raw)
    return path, sha256_bytes(raw)


def capture_page(mod, root: Path, *, start: int, end: int, rows: list[dict]):
    request = mod.build_request("BTC", start, end)
    output = root / f"page-{start}"
    authorization, authorization_hash = write_authorization(
        mod, root, request=request, output=output
    )
    return mod.execute_funding_contract(
        coin="BTC",
        start_time_ms=start,
        end_time_ms=end,
        output_dir=str(output),
        authorization_receipt=str(authorization),
        authorization_hash=authorization_hash,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
        open_once=lambda *_: FakeResponse(canonical_bytes(rows)),
    )


def independent_row_set_hash(rows: list[dict]) -> str:
    canonical_rows = sorted(canonical_bytes(row) for row in rows)
    return sha256_bytes(b"[" + b",".join(canonical_rows) + b"]")


def receipt_binding(result: dict) -> dict:
    path = Path(result["receipt_path"])
    return {"path": str(path), "file_sha256": sha256_bytes(path.read_bytes())}


def write_intent_variant(tmp_path: Path, intent: dict, name: str, mutate) -> tuple[str, str]:
    variant = json.loads(canonical_bytes(intent))
    mutate(variant)
    path = tmp_path / name
    raw = canonical_bytes(variant) + b"\n"
    path.write_bytes(raw)
    return str(path), sha256_bytes(raw)


def make_two_pages(tmp_path: Path):
    adapter = load_module(ADAPTER_PATH, "funding_contract_adapter_for_pagination_tests")
    controller = load_module(CONTROLLER_PATH, "funding_pagination_controller")
    first_rows = [
        {"coin": "BTC", "fundingRate": "0.1", "premium": "0.2", "time": 1_000},
        {"coin": "BTC", "fundingRate": "0.3", "premium": "0.4", "time": 2_000},
    ]
    second_rows = [
        {"coin": "BTC", "fundingRate": "0.3", "premium": "0.4", "time": 2_000},
        {"coin": "BTC", "fundingRate": "0.5", "premium": "0.6", "time": 3_000},
    ]
    first = capture_page(adapter, tmp_path / "first", start=1_000, end=4_000, rows=first_rows)
    second = capture_page(adapter, tmp_path / "second", start=2_000, end=4_000, rows=second_rows)
    return adapter, controller, first, second, first_rows, second_rows


def test_next_page_intent_is_offline_bounded_and_owner_authorization_free(tmp_path):
    _adapter, controller, first, _second, _rows1, _rows2 = make_two_pages(tmp_path)
    receipt = Path(first["receipt_path"])
    intent = controller.build_next_page_intent(
        predecessor_receipt_path=str(receipt),
        predecessor_receipt_sha256=sha256_bytes(receipt.read_bytes()),
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
    )
    assert intent["status"] == "NEXT_PAGE_INTENT_OFFLINE_REVIEW_REQUIRED"
    assert intent["network_fetch"] is False
    assert intent["authorization_created"] is False
    assert "authorization" not in intent
    assert intent["request"]["start_time_ms"] == 2_000
    assert intent["request"]["payload"]["endTime"] == 3_999
    assert intent["page"]["next_start_policy"] == controller.NEXT_START_POLICY
    assert intent["page"]["boundary_identity"]["next_page_must_match_exactly"] is True
    assert intent["claim_boundary"]["completeness_status"] == controller.UNKNOWN_STATUS
    assert set(intent["claim_boundary"]["authorities"].values()) == {False}
    predecessor = intent["predecessor"]
    for key in (
        "receipt_file_sha256",
        "canonical_receipt_sha256",
        "raw_sha256",
        "request_sha256",
        "source_contract_sha256",
        "adapter_sha256",
        "entrypoint_sha256",
    ):
        assert predecessor[key]

    written = controller.write_next_page_intent(intent, str(tmp_path / "intents"))
    assert Path(written["intent_path"]).read_bytes().endswith(b"\n")
    with pytest.raises(controller.FundingPaginationError, match="page_namespace_exists"):
        controller.write_next_page_intent(intent, str(tmp_path / "intents"))


def test_boundary_hash_parity_with_independent_recomputation(tmp_path):
    _adapter, _controller, first, _second, first_rows, _rows2 = make_two_pages(tmp_path)
    receipt = json.loads(Path(first["receipt_path"]).read_bytes())
    boundary_rows = [row for row in first_rows if row["time"] == 2_000]
    expected = independent_row_set_hash(boundary_rows)
    assert receipt["structure"]["max_boundary_row_set_sha256"] == expected


def test_assemble_requires_exact_boundary_identity_and_never_dedupes(tmp_path):
    _adapter, controller, first, second, _rows1, _rows2 = make_two_pages(tmp_path)
    output = tmp_path / "assembled.json"
    result = controller.assemble_pagination(
        page_receipt_bindings=[receipt_binding(first), receipt_binding(second)],
        output_path=str(output),
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
    )
    assert result["status"] == "PAGINATION_ASSEMBLY_UNKNOWN_REVIEW_REQUIRED"
    assert result["network_fetch"] is False
    assert result["raw_pages_merged"] is False
    assert result["deduplicated"] is False
    assert result["aggregate"]["row_count"] == 4
    assert result["aggregate"]["cumulative"]["page_count"] == 2
    assert result["aggregate"]["cumulative"]["row_count"] == 4
    assert result["aggregate"]["cumulative"]["raw_bytes"] == sum(
        Path(item["raw_path"]).stat().st_size for item in (first, second)
    )
    assert result["aggregate"]["completeness_status"] == controller.UNKNOWN_STATUS
    assert result["claim_boundary"]["completeness_proven"] is False
    assert set(result["claim_boundary"]["authorities"].values()) == {False}
    stored = json.loads(output.read_bytes())
    assert stored["pages"][0]["raw_sha256"] == first["raw_sha256"]
    assert stored["pages"][1]["raw_sha256"] == second["raw_sha256"]
    assert stored["pages"][1]["cumulative"]["page_count"] == 2
    assert result["source_binding"]["code_binding_status"] == "EXACT_RECEIPT_BOUND"


def test_boundary_identity_ambiguity_stops_aggregate(tmp_path):
    adapter, controller, first, _second, _rows1, _rows2 = make_two_pages(tmp_path)
    changed_rows = [
        {"coin": "BTC", "fundingRate": "DIFFERENT", "premium": "0.4", "time": 2_000},
        {"coin": "BTC", "fundingRate": "0.5", "premium": "0.6", "time": 3_000},
    ]
    changed = capture_page(
        adapter, tmp_path / "changed", start=2_000, end=4_000, rows=changed_rows
    )
    with pytest.raises(controller.FundingPaginationError, match="BOUNDARY_IDENTITY_AMBIGUOUS"):
        controller.assemble_pagination(
            page_receipt_bindings=[receipt_binding(first), receipt_binding(changed)],
            output_path=str(tmp_path / "ambiguous.json"),
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )


def test_no_progress_cycle_and_empty_stop_are_fail_closed(tmp_path):
    adapter, controller, first, _second, _rows1, _rows2 = make_two_pages(tmp_path)
    no_progress = capture_page(
        adapter,
        tmp_path / "no-progress",
        start=2_000,
        end=4_000,
        rows=[
            {"coin": "BTC", "fundingRate": "0.3", "premium": "0.4", "time": 2_000}
        ],
    )
    with pytest.raises(controller.FundingPaginationError, match="NO_PROGRESS"):
        controller.assemble_pagination(
            page_receipt_bindings=[receipt_binding(first), receipt_binding(no_progress)],
            output_path=str(tmp_path / "no-progress.json"),
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )

    with pytest.raises(controller.FundingPaginationError, match="pagination_cycle_request"):
        controller.assemble_pagination(
            page_receipt_bindings=[receipt_binding(first), receipt_binding(first)],
            output_path=str(tmp_path / "cycle.json"),
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )

    empty = capture_page(adapter, tmp_path / "empty", start=1_000, end=4_000, rows=[])
    decision = controller.build_next_page_intent(
        predecessor_receipt_path=empty["receipt_path"],
        predecessor_receipt_sha256=sha256_bytes(Path(empty["receipt_path"]).read_bytes()),
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
    )
    assert decision["status"] == "STOP_EMPTY_PAGE_REVIEW_REQUIRED"
    assert decision["claim_boundary"]["completeness_proven"] is False


def test_limits_stop_without_authorization_or_network(tmp_path):
    _adapter, controller, first, _second, _rows1, _rows2 = make_two_pages(tmp_path)
    receipt = Path(first["receipt_path"])
    decision = controller.build_next_page_intent(
        predecessor_receipt_path=str(receipt),
        predecessor_receipt_sha256=sha256_bytes(receipt.read_bytes()),
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
        max_pages=1,
    )
    assert decision["status"] == "STOP_MAX_PAGES_REVIEW_REQUIRED"
    assert decision["network_fetch"] is False
    assert decision["authorization_created"] is False


def test_page_number_is_derived_from_anchored_intent_lineage(tmp_path):
    _adapter, controller, first, second, _rows1, _rows2 = make_two_pages(tmp_path)
    first_path = Path(first["receipt_path"])
    first_intent = controller.build_next_page_intent(
        predecessor_receipt_path=str(first_path),
        predecessor_receipt_sha256=sha256_bytes(first_path.read_bytes()),
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
    )
    written = controller.write_next_page_intent(first_intent, str(tmp_path / "lineage"))
    second_path = Path(second["receipt_path"])
    decision = controller.build_next_page_intent(
        predecessor_receipt_path=str(second_path),
        predecessor_receipt_sha256=sha256_bytes(second_path.read_bytes()),
        predecessor_intent_path=written["intent_path"],
        predecessor_intent_sha256=written["intent_file_sha256"],
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
        max_pages=2,
    )
    assert decision["status"] == "STOP_MAX_PAGES_REVIEW_REQUIRED"
    assert decision["page"]["page_number"] == 2
    assert decision["lineage"]["kind"] == "INTENT_BOUND"

    with pytest.raises(controller.FundingPaginationError, match="missing_pagination_lineage"):
        controller.build_next_page_intent(
            predecessor_receipt_path=str(second_path),
            predecessor_receipt_sha256=sha256_bytes(second_path.read_bytes()),
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )

    forged_path, forged_sha = write_intent_variant(
        tmp_path,
        first_intent,
        "forged-page-number.json",
        lambda value: value["page"].update(page_number=99, predecessor_page_number=98),
    )
    with pytest.raises(controller.FundingPaginationError, match="page_number_invalid"):
        controller.build_next_page_intent(
            predecessor_receipt_path=str(second_path),
            predecessor_receipt_sha256=sha256_bytes(second_path.read_bytes()),
            predecessor_intent_path=forged_path,
            predecessor_intent_sha256=forged_sha,
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
            max_pages=2,
        )

    with pytest.raises(controller.FundingPaginationError, match="current_request_mismatch"):
        controller.build_next_page_intent(
            predecessor_receipt_path=str(first_path),
            predecessor_receipt_sha256=sha256_bytes(first_path.read_bytes()),
            predecessor_intent_path=written["intent_path"],
            predecessor_intent_sha256=written["intent_file_sha256"],
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )

    boundary_path, boundary_sha = write_intent_variant(
        tmp_path,
        first_intent,
        "forged-boundary.json",
        lambda value: value["page"]["boundary_identity"].update(
            predecessor_row_set_sha256="b" * 64
        ),
    )
    with pytest.raises(controller.FundingPaginationError, match="boundary_mismatch"):
        controller.build_next_page_intent(
            predecessor_receipt_path=str(second_path),
            predecessor_receipt_sha256=sha256_bytes(second_path.read_bytes()),
            predecessor_intent_path=boundary_path,
            predecessor_intent_sha256=boundary_sha,
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )


def test_intent_cursor_is_bound_to_predecessor_max_time(tmp_path):
    _adapter, controller, first, second, _rows1, _rows2 = make_two_pages(tmp_path)
    first_path = Path(first["receipt_path"])
    first_intent = controller.build_next_page_intent(
        predecessor_receipt_path=str(first_path),
        predecessor_receipt_sha256=sha256_bytes(first_path.read_bytes()),
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
    )
    forged_path, forged_sha = write_intent_variant(
        tmp_path,
        first_intent,
        "forged-cursor.json",
        lambda value: (
            value["request"]["payload"].update(startTime=1_999),
            value["request"].update(start_time_ms=1_999),
            value["request"].update(
                sha256=sha256_bytes(canonical_bytes(value["request"]["payload"]))
            ),
        ),
    )
    second_path = Path(second["receipt_path"])
    with pytest.raises(controller.FundingPaginationError, match="cursor_mismatch"):
        controller.build_next_page_intent(
            predecessor_receipt_path=str(second_path),
            predecessor_receipt_sha256=sha256_bytes(second_path.read_bytes()),
            predecessor_intent_path=forged_path,
            predecessor_intent_sha256=forged_sha,
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )


def test_cumulative_lineage_limits_are_recomputed_and_anchored(tmp_path):
    adapter, controller, first, second, _rows1, _rows2 = make_two_pages(tmp_path)
    third = capture_page(
        adapter,
        tmp_path / "third",
        start=3_000,
        end=4_000,
        rows=[
            {"coin": "BTC", "fundingRate": "0.5", "premium": "0.6", "time": 3_000}
        ],
    )
    first_path = Path(first["receipt_path"])
    first_intent = controller.build_next_page_intent(
        predecessor_receipt_path=str(first_path),
        predecessor_receipt_sha256=sha256_bytes(first_path.read_bytes()),
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
    )
    first_written = controller.write_next_page_intent(
        first_intent, str(tmp_path / "lineage")
    )
    second_path = Path(second["receipt_path"])
    second_intent = controller.build_next_page_intent(
        predecessor_receipt_path=str(second_path),
        predecessor_receipt_sha256=sha256_bytes(second_path.read_bytes()),
        predecessor_intent_path=first_written["intent_path"],
        predecessor_intent_sha256=first_written["intent_file_sha256"],
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
    )
    assert second_intent["cumulative"]["page_count"] == 2
    assert second_intent["cumulative"]["row_count"] == 4
    second_written = controller.write_next_page_intent(
        second_intent, str(tmp_path / "lineage")
    )
    third_path = Path(third["receipt_path"])
    limited = controller.build_next_page_intent(
        predecessor_receipt_path=str(third_path),
        predecessor_receipt_sha256=sha256_bytes(third_path.read_bytes()),
        predecessor_intent_path=second_written["intent_path"],
        predecessor_intent_sha256=second_written["intent_file_sha256"],
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
        max_rows=4,
    )
    assert limited["status"] == "STOP_MAX_ROWS_REVIEW_REQUIRED"
    assert limited["cumulative"]["page_count"] == 3
    assert limited["cumulative"]["row_count"] == 5

    byte_limited = controller.build_next_page_intent(
        predecessor_receipt_path=str(third_path),
        predecessor_receipt_sha256=sha256_bytes(third_path.read_bytes()),
        predecessor_intent_path=second_written["intent_path"],
        predecessor_intent_sha256=second_written["intent_file_sha256"],
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
        max_bytes=limited["cumulative"]["raw_bytes"] - 1,
    )
    assert byte_limited["status"] == "STOP_MAX_BYTES_REVIEW_REQUIRED"

    forged_path, forged_sha = write_intent_variant(
        tmp_path,
        second_intent,
        "forged-cumulative.json",
        lambda value: value["cumulative"].update(row_count=0, raw_bytes=0),
    )
    with pytest.raises(controller.FundingPaginationError, match="cumulative_mismatch"):
        controller.build_next_page_intent(
            predecessor_receipt_path=str(third_path),
            predecessor_receipt_sha256=sha256_bytes(third_path.read_bytes()),
            predecessor_intent_path=forged_path,
            predecessor_intent_sha256=forged_sha,
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )

    with pytest.raises(controller.FundingPaginationError, match="page_number_invalid"):
        controller.build_next_page_intent(
            predecessor_receipt_path=str(third_path),
            predecessor_receipt_sha256=sha256_bytes(third_path.read_bytes()),
            predecessor_intent_path=second_written["intent_path"],
            predecessor_intent_sha256=second_written["intent_file_sha256"],
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
            max_pages=2,
        )


def test_raw_verification_uses_one_fd_bytes_and_rejects_swap_or_nonregular(
    tmp_path, monkeypatch
):
    _adapter, controller, first, _second, _rows1, _rows2 = make_two_pages(tmp_path)
    receipt_path = Path(first["receipt_path"])
    receipt = json.loads(receipt_path.read_bytes())
    raw_path = Path(receipt["raw"]["path"])
    original_raw = raw_path.read_bytes()
    real_reader = controller._read_regular_nofollow
    observed = []

    def read_then_swap(path, error):
        data = real_reader(path, error)
        if path == raw_path:
            observed.append(data)
            raw_path.write_bytes(b"[]")
        return data

    monkeypatch.setattr(controller, "_read_regular_nofollow", read_then_swap)
    loaded = controller._load_receipt(
        str(receipt_path),
        expected_file_sha256=sha256_bytes(receipt_path.read_bytes()),
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
    )
    assert observed == [original_raw]
    assert loaded["raw_sha256"] == sha256_bytes(original_raw)

    symlink = tmp_path / "raw-link"
    symlink.symlink_to(raw_path)
    receipt["raw"]["path"] = str(symlink)
    receipt["raw"]["sha256"] = sha256_bytes(raw_path.read_bytes())
    receipt_path.write_bytes(canonical_bytes(receipt) + b"\n")
    with pytest.raises(controller.FundingPaginationError, match="path_not_canonical_absolute"):
        controller._load_receipt(
            str(receipt_path),
            expected_file_sha256=sha256_bytes(receipt_path.read_bytes()),
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )

    nonregular = tmp_path / "raw-directory"
    nonregular.mkdir()
    receipt["raw"]["path"] = str(nonregular)
    receipt["raw"]["sha256"] = "0" * 64
    receipt_path.write_bytes(canonical_bytes(receipt) + b"\n")
    with pytest.raises(controller.FundingPaginationError, match="not_regular"):
        controller._load_receipt(
            str(receipt_path),
            expected_file_sha256=sha256_bytes(receipt_path.read_bytes()),
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )


def test_legacy_receipt_code_binding_stays_review_only(tmp_path):
    _adapter, controller, first, _second, _rows1, _rows2 = make_two_pages(tmp_path)
    path = Path(first["receipt_path"])
    receipt = json.loads(path.read_bytes())
    receipt["authorization"].pop("adapter_sha256")
    receipt["authorization"].pop("entrypoint_sha256")
    path.write_bytes(canonical_bytes(receipt) + b"\n")
    binding = receipt_binding({"receipt_path": str(path)})
    intent = controller.build_next_page_intent(
        predecessor_receipt_path=str(path),
        predecessor_receipt_sha256=binding["file_sha256"],
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
    )
    assert (
        intent["predecessor"]["code_binding_status"]
        == "LEGACY_RECEIPT_CODE_HASHES_NOT_RECORDED_REVIEW_REQUIRED"
    )
    assert set(intent["claim_boundary"]["authorities"].values()) == {False}
    assembled = controller.assemble_pagination(
        page_receipt_bindings=[binding],
        output_path=str(tmp_path / "legacy-assembled.json"),
        sealed_start_time_ms=1_000,
        sealed_end_exclusive_ms=4_000,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
    )
    assert (
        assembled["source_binding"]["code_binding_status"]
        == "LEGACY_RECEIPT_CODE_HASHES_NOT_RECORDED_REVIEW_REQUIRED"
    )
    assert assembled["claim_boundary"]["structural_readiness"] == (
        "LEGACY_REVIEW_REQUIRED_NO_DOWNSTREAM_PROMOTION"
    )


def test_assembly_requires_exact_receipt_file_bindings_and_safety_fields(tmp_path):
    adapter, controller, first, second, _rows1, _rows2 = make_two_pages(tmp_path)
    with pytest.raises(controller.FundingPaginationError, match="binding_sha_required"):
        controller.assemble_pagination(
            page_receipt_bindings=[first["receipt_path"], receipt_binding(second)],
            output_path=str(tmp_path / "path-only.json"),
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )
    with pytest.raises(controller.FundingPaginationError, match="receipt_hash_mismatch"):
        controller.assemble_pagination(
            page_receipt_bindings=[
                {"path": first["receipt_path"], "file_sha256": "0" * 64},
                receipt_binding(second),
            ],
            output_path=str(tmp_path / "wrong-sha.json"),
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )

    receipt_path = Path(first["receipt_path"])
    original_sha = sha256_bytes(receipt_path.read_bytes())
    receipt = json.loads(receipt_path.read_bytes())
    receipt["source"]["query_type"] = "other"
    receipt_path.write_bytes(canonical_bytes(receipt) + b"\n")
    with pytest.raises(controller.FundingPaginationError, match="receipt_hash_mismatch"):
        controller.assemble_pagination(
            page_receipt_bindings=[
                {"path": str(receipt_path), "file_sha256": original_sha},
                receipt_binding(second),
            ],
            output_path=str(tmp_path / "rewritten.json"),
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )

    fresh = capture_page(
        adapter,
        tmp_path / "safety",
        start=1_000,
        end=4_000,
        rows=[
            {"coin": "BTC", "fundingRate": "0.1", "premium": "0.2", "time": 1_000},
            {"coin": "BTC", "fundingRate": "0.3", "premium": "0.4", "time": 2_000},
        ],
    )
    fresh_path = Path(fresh["receipt_path"])
    fresh_receipt = json.loads(fresh_path.read_bytes())
    fresh_receipt["structure"]["gap_count"] = 0
    fresh_path.write_bytes(canonical_bytes(fresh_receipt) + b"\n")
    with pytest.raises(controller.FundingPaginationError, match="gap_count"):
        controller.assemble_pagination(
            page_receipt_bindings=[receipt_binding({"receipt_path": str(fresh_path)})],
            output_path=str(tmp_path / "gap-promoted.json"),
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )

    under = capture_page(
        adapter,
        tmp_path / "underreported",
        start=1_000,
        end=4_000,
        rows=[
            {"coin": "BTC", "fundingRate": "0.1", "premium": "0.2", "time": 1_000},
            {"coin": "BTC", "fundingRate": "0.3", "premium": "0.4", "time": 2_000},
        ],
    )
    under_path = Path(under["receipt_path"])
    under_receipt = json.loads(under_path.read_bytes())
    under_receipt["structure"]["row_count"] = 1
    under_path.write_bytes(canonical_bytes(under_receipt) + b"\n")
    with pytest.raises(controller.FundingPaginationError, match="row_count_mismatch"):
        controller.assemble_pagination(
            page_receipt_bindings=[receipt_binding({"receipt_path": str(under_path)})],
            output_path=str(tmp_path / "row-underreported.json"),
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )


@pytest.mark.parametrize(
    ("section", "key", "value", "error"),
    [
        ("source", "query_type", "other", "source_binding_mismatch"),
        (None, "status", "NOT_TERMINAL", "terminal_status_invalid"),
        ("authorization", "acquisition_kind", "BOGUS", "acquisition_kind_invalid"),
        ("transport", "http_requests", 0, "http_request_count_invalid"),
        ("claim_boundary", "downstream_allowed", True, "claim_boundary_invalid"),
    ],
)
def test_receipt_safety_fields_are_exactly_verified(
    tmp_path, section, key, value, error
):
    adapter = load_module(ADAPTER_PATH, f"funding_contract_adapter_safety_{key}")
    controller = load_module(CONTROLLER_PATH, f"funding_pagination_controller_safety_{key}")
    result = capture_page(
        adapter,
        tmp_path / key,
        start=1_000,
        end=4_000,
        rows=[
            {"coin": "BTC", "fundingRate": "0.1", "premium": "0.2", "time": 1_000},
            {"coin": "BTC", "fundingRate": "0.3", "premium": "0.4", "time": 2_000},
        ],
    )
    path = Path(result["receipt_path"])
    receipt = json.loads(path.read_bytes())
    (receipt if section is None else receipt[section])[key] = value
    path.write_bytes(canonical_bytes(receipt) + b"\n")
    with pytest.raises(controller.FundingPaginationError, match=error):
        controller.assemble_pagination(
            page_receipt_bindings=[receipt_binding({"receipt_path": str(path)})],
            output_path=str(tmp_path / f"{key}.json"),
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )
