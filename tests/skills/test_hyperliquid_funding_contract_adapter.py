from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import urllib.error
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


def load_module():
    spec = importlib.util.spec_from_file_location("funding_contract_adapter", ADAPTER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
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


def write_authorization(mod, tmp_path: Path, *, request: dict, output_dir: Path):
    marker = tmp_path / "authorization-consumed.json"
    payload = {
        "schema_version": mod.AUTHORIZATION_SCHEMA,
        "authorization_id": "owner-test-authorization",
        "command": mod.COMMAND,
        "endpoint": mod.ENDPOINT,
        "source_contract_sha256": "a" * 64,
        "request_sha256": sha256_bytes(canonical_bytes(request)),
        "coin": request["coin"],
        "start_time_ms": request["startTime"],
        "end_time_ms": request["endTime"],
        "output_dir": str(output_dir),
        "consumption_marker_path": str(marker),
        "maximum_http_requests": 1,
        "adapter_sha256": sha256_bytes(ADAPTER_PATH.read_bytes()),
        "entrypoint_sha256": sha256_bytes(ENTRYPOINT_PATH.read_bytes()),
        "network_fetch": True,
        "authorities": {key: False for key in mod.AUTHORITY_KEYS},
    }
    raw = canonical_bytes(payload) + b"\n"
    path = tmp_path / "authorization.json"
    path.write_bytes(raw)
    return path, sha256_bytes(raw), marker


class FakeResponse:
    status = 200

    def __init__(self, body: bytes, *, content_type: str = "application/json"):
        self.body = body
        self.headers = {"Content-Type": content_type, "Content-Encoding": ""}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def getcode(self):
        return self.status

    def read(self):
        return self.body


def execute(mod, tmp_path: Path, body: bytes, *, open_once=None):
    request = mod.build_request("BTC", 1_000, 4_000)
    output_dir = tmp_path / "capture"
    authorization, authorization_hash, marker = write_authorization(
        mod,
        tmp_path,
        request=request,
        output_dir=output_dir,
    )
    calls = []

    def default_open(request_object, timeout):
        calls.append((request_object, timeout))
        return FakeResponse(body)

    result = mod.execute_funding_contract(
        coin="BTC",
        start_time_ms=1_000,
        end_time_ms=4_000,
        output_dir=str(output_dir),
        authorization_receipt=str(authorization),
        authorization_hash=authorization_hash,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
        open_once=open_once or default_open,
    )
    return result, calls, marker, output_dir


def test_exact_wire_bytes_raw_first_and_performance_blind_receipt(tmp_path, monkeypatch):
    mod = load_module()
    response_payload = [
        {"coin": "BTC", "fundingRate": "0.0001", "premium": "0.0002", "time": 1_000},
        {"coin": "BTC", "fundingRate": "-0.0001", "premium": "-0.0002", "time": 2_000},
    ]
    body = canonical_bytes(response_payload)
    output_dir = tmp_path / "capture"
    real_loads = mod.json.loads

    def observed_loads(value, *args, **kwargs):
        if value == body:
            raw_path = output_dir / "response.raw"
            assert raw_path.exists()
            assert raw_path.read_bytes() == body
        return real_loads(value, *args, **kwargs)

    monkeypatch.setattr(mod.json, "loads", observed_loads)
    result, calls, marker, _ = execute(mod, tmp_path, body)

    assert len(calls) == 1
    sent_request, timeout = calls[0]
    expected_request = {
        "coin": "BTC",
        "endTime": 4_000,
        "startTime": 1_000,
        "type": "fundingHistory",
    }
    assert sent_request.full_url == mod.ENDPOINT
    assert sent_request.method == "POST"
    assert sent_request.data == canonical_bytes(expected_request)
    assert (output_dir / "request.json").read_bytes() == sent_request.data
    assert timeout == mod.TIMEOUT_SECONDS
    assert marker.exists()
    assert result["status"] == "RAW_ACQUIRED_STRUCTURE_PASS_COMPLETENESS_NOT_PROVEN"

    receipt = json.loads((output_dir / "receipt.json").read_bytes())
    assert receipt["transport"]["http_requests"] == 1
    assert receipt["transport"]["automatic_retries"] == 0
    assert receipt["structure"]["completeness_status"] == "NOT_PROVEN"
    assert receipt["claim_boundary"]["strategy_authorized"] is False
    rendered = json.dumps(receipt, sort_keys=True)
    for forbidden in ("0.0001", "-0.0001", "average", "return", "profit"):
        assert forbidden not in rendered


def test_json_and_structure_failures_keep_raw_and_never_claim_completeness(tmp_path):
    mod = load_module()
    result, calls, _marker, output_dir = execute(mod, tmp_path, b"not-json")
    assert len(calls) == 1
    assert (output_dir / "response.raw").read_bytes() == b"not-json"
    assert result["status"] == "RAW_CAPTURED_JSON_INVALID"

    second = tmp_path / "second"
    second.mkdir()
    request = mod.build_request("BTC", 1_000, 4_000)
    output = second / "capture"
    authorization, authorization_hash, _marker = write_authorization(
        mod, second, request=request, output_dir=output
    )
    invalid_shape = canonical_bytes(
        [{"coin": "BTC", "fundingRate": "0.1", "premium": "0.2", "time": 9_000}]
    )
    result = mod.execute_funding_contract(
        coin="BTC",
        start_time_ms=1_000,
        end_time_ms=4_000,
        output_dir=str(output),
        authorization_receipt=str(authorization),
        authorization_hash=authorization_hash,
        adapter_path=ADAPTER_PATH,
        entrypoint_path=ENTRYPOINT_PATH,
        open_once=lambda _request, _timeout: FakeResponse(invalid_shape),
    )
    assert result["status"] == "RAW_CAPTURED_STRUCTURE_INVALID"
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["claim_boundary"]["completeness_proven"] is False


def test_http_failure_consumes_authorization_and_cannot_retry(tmp_path):
    mod = load_module()
    request = mod.build_request("BTC", 1_000, 4_000)
    output_dir = tmp_path / "capture"
    authorization, authorization_hash, marker = write_authorization(
        mod, tmp_path, request=request, output_dir=output_dir
    )
    calls = []

    def fail_once(request_object, _timeout):
        calls.append(request_object)
        raise urllib.error.HTTPError(mod.ENDPOINT, 429, "rate limited", {}, None)

    kwargs = {
        "coin": "BTC",
        "start_time_ms": 1_000,
        "end_time_ms": 4_000,
        "output_dir": str(output_dir),
        "authorization_receipt": str(authorization),
        "authorization_hash": authorization_hash,
        "adapter_path": ADAPTER_PATH,
        "entrypoint_path": ENTRYPOINT_PATH,
        "open_once": fail_once,
    }
    with pytest.raises(mod.FundingContractError, match="single_request_failed"):
        mod.execute_funding_contract(**kwargs)
    assert len(calls) == 1
    assert marker.exists()

    with pytest.raises(mod.FundingContractError, match="authorization_already_consumed"):
        mod.execute_funding_contract(**kwargs)
    assert len(calls) == 1


def test_preflight_binding_or_output_collision_never_calls_transport(tmp_path):
    mod = load_module()
    request = mod.build_request("BTC", 1_000, 4_000)
    output_dir = tmp_path / "capture"
    authorization, authorization_hash, marker = write_authorization(
        mod, tmp_path, request=request, output_dir=output_dir
    )
    calls = []
    kwargs = {
        "coin": "BTC",
        "start_time_ms": 1_000,
        "end_time_ms": 4_000,
        "output_dir": str(output_dir),
        "authorization_receipt": str(authorization),
        "authorization_hash": authorization_hash,
        "adapter_path": ADAPTER_PATH,
        "entrypoint_path": ENTRYPOINT_PATH,
        "open_once": lambda *_args: calls.append(True),
    }
    with pytest.raises(mod.FundingContractError, match="authorization_binding_mismatch:request_sha256"):
        mod.execute_funding_contract(**{**kwargs, "coin": "ETH"})
    assert calls == []
    assert not marker.exists()

    output_dir.mkdir()
    with pytest.raises(mod.FundingContractError, match="output_dir_must_not_exist"):
        mod.execute_funding_contract(**kwargs)
    assert calls == []
    assert not marker.exists()


@pytest.mark.parametrize(
    "coin,start,end,error",
    [
        (" btc", 1, 2, "coin_must_be_exact"),
        ("BTC", 2, 2, "invalid_half_open_window"),
        ("BTC", 3, 2, "invalid_half_open_window"),
        ("BTC", True, 2, "start_time_ms_must_be_integer"),
    ],
)
def test_request_rejects_implicit_normalization_and_invalid_windows(coin, start, end, error):
    mod = load_module()
    with pytest.raises(mod.FundingContractError, match=error):
        mod.build_request(coin, start, end)
