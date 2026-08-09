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
        page_receipt_paths=[first["receipt_path"], second["receipt_path"]],
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
    assert result["aggregate"]["completeness_status"] == controller.UNKNOWN_STATUS
    assert result["claim_boundary"]["completeness_proven"] is False
    assert set(result["claim_boundary"]["authorities"].values()) == {False}
    stored = json.loads(output.read_bytes())
    assert stored["pages"][0]["raw_sha256"] == first["raw_sha256"]
    assert stored["pages"][1]["raw_sha256"] == second["raw_sha256"]


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
            page_receipt_paths=[first["receipt_path"], changed["receipt_path"]],
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
            page_receipt_paths=[first["receipt_path"], no_progress["receipt_path"]],
            output_path=str(tmp_path / "no-progress.json"),
            sealed_start_time_ms=1_000,
            sealed_end_exclusive_ms=4_000,
            adapter_path=ADAPTER_PATH,
            entrypoint_path=ENTRYPOINT_PATH,
        )

    with pytest.raises(controller.FundingPaginationError, match="pagination_cycle_request"):
        controller.assemble_pagination(
            page_receipt_paths=[first["receipt_path"], first["receipt_path"]],
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
