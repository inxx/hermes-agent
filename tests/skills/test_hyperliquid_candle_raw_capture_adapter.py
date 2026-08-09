from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import urllib.error

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER_PATH = (
    REPO_ROOT
    / "optional-skills"
    / "blockchain"
    / "hyperliquid"
    / "scripts"
    / "candle_raw_capture_adapter.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location("candle_raw_capture_adapter", ADAPTER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def clear_credential_environment(monkeypatch):
    for key in (
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
    ):
        monkeypatch.delenv(key, raising=False)


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
    def __init__(self, body: bytes, *, status: int = 200, content_type: str = "application/json"):
        self.body = body
        self.status = status
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def getcode(self):
        return self.status

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


def write_run_intent(mod, tmp_path: Path, *, interval: str, output_dir: Path):
    output_dir = output_dir.resolve()
    request = mod.build_request(interval=interval, start_time_ms=1_000, end_time_ms=61_000)
    marker = output_dir.parent / f".{output_dir.name}.consumed"
    intent = {
        "schema_version": mod.RUN_INTENT_SCHEMA,
        "run_id": "owner-run-001",
        "command": mod.COMMAND,
        "endpoint": mod.ENDPOINT,
        "request": request,
        "request_sha256": sha256_bytes(canonical_bytes(request)),
        "output_dir": str(output_dir),
        "consumption_marker_path": str(marker),
        "adapter_sha256": sha256_bytes(ADAPTER_PATH.read_bytes()),
        "source_contract_sha256": mod.SOURCE_CONTRACT_SHA256,
        "maximum_http_requests": 1,
        "retries": 0,
        "redirects": 0,
        "network_fetch": True,
        "authorities": dict(mod.ALL_AUTHORITIES_FALSE),
    }
    path = tmp_path / "run-intent.json"
    raw = canonical_bytes(intent) + b"\n"
    path.write_bytes(raw)
    return path, sha256_bytes(raw), marker


def candle(*, t: int, close: int, interval: str = "1m") -> dict:
    return {
        "t": t,
        "T": close,
        "s": "BTC",
        "i": interval,
        "o": "50000",
        "h": "50100",
        "l": "49900",
        "c": "50050",
        "v": "12.5",
        "n": 42,
    }


def test_one_shot_raw_first_filters_only_local_completed_rows(tmp_path, monkeypatch):
    mod = load_module()
    output = tmp_path / "capture"
    intent, intent_hash, marker = write_run_intent(mod, tmp_path, interval="1m", output_dir=output)
    body = canonical_bytes([candle(t=8_000, close=9_000), candle(t=9_500, close=10_500)])
    calls = []

    def opener(request, timeout):
        calls.append((request, timeout))
        return FakeResponse(body)

    result = mod.capture_candles(
        interval="1m",
        start_time_ms=1_000,
        end_time_ms=61_000,
        output_dir=str(output.resolve()),
        run_intent=str(intent),
        run_intent_hash=intent_hash,
        open_once=opener,
        wall_ms=iter([10_000, 10_020]).__next__,
        monotonic_ns=iter([100, 150]).__next__,
    )

    assert len(calls) == 1
    request, timeout = calls[0]
    assert request.full_url == mod.ENDPOINT
    assert request.method == "POST"
    assert request.data == canonical_bytes(mod.build_request(interval="1m", start_time_ms=1_000, end_time_ms=61_000))
    assert timeout == mod.TIMEOUT_SECONDS
    assert marker.exists()
    assert (output / "request.json").read_bytes() == request.data
    assert (output / "response.raw").read_bytes() == body
    assert result["completed_row_count"] == 1

    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["timing"] == {
        "request_start_wall_ms": 10_000,
        "response_complete_wall_ms": 10_020,
        "monotonic_elapsed_ns": 50,
    }
    assert receipt["structural_rows"][0]["local_close_boundary_elapsed_ms"] == 1_000
    assert "source_sequence" not in receipt["structural_rows"][0]
    assert "available_time_ms" not in receipt["structural_rows"][0]
    assert receipt["structure"]["source_publication"] == "UNKNOWN/REVIEW_REQUIRED"
    assert receipt["claim_boundary"]["strategy"] is False
    assert receipt["claim_boundary"]["realtime"] is False
    assert receipt["claim_boundary"]["causal"] is False
    assert receipt["authorities"] == mod.ALL_AUTHORITIES_FALSE


def test_raw_is_durable_before_parse_and_exact_schema_is_fail_closed(tmp_path):
    mod = load_module()
    output = tmp_path / "capture"
    intent, intent_hash, _marker = write_run_intent(mod, tmp_path, interval="1m", output_dir=output)
    invalid = candle(t=8_000, close=9_000)
    invalid["extra"] = "forbidden"
    body = canonical_bytes([invalid])

    with pytest.raises(mod.CandleCaptureError, match="candle_row_exact_schema_invalid"):
        mod.capture_candles(
            interval="1m",
            start_time_ms=1_000,
            end_time_ms=61_000,
            output_dir=str(output.resolve()),
            run_intent=str(intent),
            run_intent_hash=intent_hash,
            open_once=lambda _request, _timeout: FakeResponse(body),
            wall_ms=iter([10_000, 10_020]).__next__,
            monotonic_ns=iter([100, 150]).__next__,
        )
    assert (output / "response.raw").read_bytes() == body


def test_duplicate_keys_are_rejected_for_intent_and_raw(tmp_path):
    mod = load_module()
    output = tmp_path / "capture"
    intent, intent_hash, _marker = write_run_intent(mod, tmp_path, interval="1m", output_dir=output)
    duplicate_intent = intent.with_name("duplicate-intent.json")
    duplicate_intent.write_bytes(
        b'{"schema_version":"x","schema_version":"y"}'
    )
    with pytest.raises(mod.CandleCaptureError, match="run_intent_unreadable_or_invalid"):
        mod.capture_candles(
            interval="1m",
            start_time_ms=1_000,
            end_time_ms=61_000,
            output_dir=str(output.resolve()),
            run_intent=str(duplicate_intent.resolve()),
            run_intent_hash=sha256_bytes(duplicate_intent.read_bytes()),
            open_once=lambda *_: pytest.fail("network must not run"),
        )

    raw_output = tmp_path / "raw-duplicate"
    raw_intent, raw_intent_hash, _marker = write_run_intent(
        mod, tmp_path, interval="1m", output_dir=raw_output
    )
    duplicate_raw = b'[{"t":1,"t":1,"T":2,"s":"BTC","i":"1m","o":"1","h":"1","l":"1","c":"1","v":"1","n":1}]'
    with pytest.raises(mod.CandleCaptureError, match="raw_json_invalid"):
        mod.capture_candles(
            interval="1m",
            start_time_ms=1_000,
            end_time_ms=61_000,
            output_dir=str(raw_output.resolve()),
            run_intent=str(raw_intent.resolve()),
            run_intent_hash=raw_intent_hash,
            open_once=lambda _request, _timeout: FakeResponse(duplicate_raw),
            wall_ms=iter([10_000, 10_020]).__next__,
            monotonic_ns=iter([100, 150]).__next__,
        )
    assert (raw_output / "response.raw").read_bytes() == duplicate_raw


def test_decimal_and_clock_rollback_rules_fail_closed(tmp_path):
    mod = load_module()
    for field, value, error in (
        ("o", "-1", "candle_row_o_invalid"),
        ("v", "01.0", "candle_row_v_invalid"),
        ("c", "NaN", "candle_row_c_invalid"),
    ):
        output = tmp_path / field
        intent, intent_hash, _marker = write_run_intent(mod, tmp_path, interval="1m", output_dir=output)
        row = candle(t=8_000, close=9_000)
        row[field] = value
        with pytest.raises(mod.CandleCaptureError, match=error):
            mod.capture_candles(
                interval="1m",
                start_time_ms=1_000,
                end_time_ms=61_000,
                output_dir=str(output.resolve()),
                run_intent=str(intent.resolve()),
                run_intent_hash=intent_hash,
                open_once=lambda _request, _timeout, row=row: FakeResponse(canonical_bytes([row])),
                wall_ms=iter([10_000, 10_020]).__next__,
                monotonic_ns=iter([100, 150]).__next__,
            )

    for wall_values, mono_values, error in (
        ([10_000, 9_999], [100, 150], "wall_clock_rollback"),
        ([10_000, 10_020], [100, 99], "monotonic_clock_rollback"),
    ):
        output = tmp_path / error
        intent, intent_hash, _marker = write_run_intent(mod, tmp_path, interval="1m", output_dir=output)
        with pytest.raises(mod.CandleCaptureError, match=error):
            mod.capture_candles(
                interval="1m",
                start_time_ms=1_000,
                end_time_ms=61_000,
                output_dir=str(output.resolve()),
                run_intent=str(intent.resolve()),
                run_intent_hash=intent_hash,
                open_once=lambda _request, _timeout: FakeResponse(canonical_bytes([candle(t=8_000, close=9_000)])),
                wall_ms=iter(wall_values).__next__,
                monotonic_ns=iter(mono_values).__next__,
            )


def test_credentials_are_denied_before_opener_and_run_intent_is_consumed_once(tmp_path, monkeypatch):
    mod = load_module()
    output = tmp_path / "capture"
    intent, intent_hash, marker = write_run_intent(mod, tmp_path, interval="1m", output_dir=output)
    calls = []
    monkeypatch.setenv("HYPERLIQUID_PRIVATE_KEY", "")
    with pytest.raises(mod.CandleCaptureError, match="credential_env_denied"):
        mod.capture_candles(
            interval="1m",
            start_time_ms=1_000,
            end_time_ms=61_000,
            output_dir=str(output.resolve()),
            run_intent=str(intent),
            run_intent_hash=intent_hash,
            open_once=lambda *_args: calls.append(True),
        )
    assert calls == []
    assert not marker.exists()

    monkeypatch.delenv("HYPERLIQUID_PRIVATE_KEY")
    body = canonical_bytes([candle(t=8_000, close=9_000)])
    kwargs = {
        "interval": "1m",
        "start_time_ms": 1_000,
        "end_time_ms": 61_000,
        "output_dir": str(output),
        "run_intent": str(intent),
        "run_intent_hash": intent_hash,
        "open_once": lambda _request, _timeout: FakeResponse(body),
        "wall_ms": iter([10_000, 10_020]).__next__,
        "monotonic_ns": iter([100, 150]).__next__,
    }
    mod.capture_candles(**kwargs)
    with pytest.raises(mod.CandleCaptureError, match="run_intent_already_consumed"):
        mod.capture_candles(**kwargs)


@pytest.mark.parametrize(
    "denied_name",
    [
        "HL_PRIVATE_KEY",
        "EXCHANGE_API_KEY",
        "ORDER_SIGNING_KEY",
        "CAPITAL_ALLOCATION_TOKEN",
        "LIVE_TRADING",
        "PAPER_TRADING",
        "ORDER_SUBMISSION",
        "BROKER_URL",
    ],
)
def test_trading_authority_environment_is_denied_before_opener(tmp_path, monkeypatch, denied_name):
    mod = load_module()
    output = tmp_path / "capture"
    intent, intent_hash, marker = write_run_intent(mod, tmp_path, interval="1m", output_dir=output)
    calls = []
    monkeypatch.setenv(denied_name, "1")

    with pytest.raises(mod.CandleCaptureError, match=f"credential_env_denied:{denied_name}"):
        mod.capture_candles(
            interval="1m",
            start_time_ms=1_000,
            end_time_ms=61_000,
            output_dir=str(output.resolve()),
            run_intent=str(intent),
            run_intent_hash=intent_hash,
            open_once=lambda *_args: calls.append(True),
        )

    assert calls == []
    assert not marker.exists()


@pytest.mark.parametrize("failure", ["timeout", "http", "redirect"])
def test_transport_failures_make_one_attempt_without_retry(tmp_path, failure):
    mod = load_module()
    output = tmp_path / failure
    intent, intent_hash, marker = write_run_intent(mod, tmp_path, interval="1m", output_dir=output)
    calls = []

    def opener(request, timeout):
        calls.append((request, timeout))
        if failure == "timeout":
            raise TimeoutError("timeout")
        if failure == "http":
            raise urllib.error.HTTPError(request.full_url, 429, "rate limited", {}, None)
        return FakeResponse(b"redirect", status=302)

    with pytest.raises(mod.CandleCaptureError):
        mod.capture_candles(
            interval="1m",
            start_time_ms=1_000,
            end_time_ms=61_000,
            output_dir=str(output.resolve()),
            run_intent=str(intent),
            run_intent_hash=intent_hash,
            open_once=opener,
        )
    assert len(calls) == 1
    assert marker.exists()


def test_cli_is_one_shot_entrypoint_without_scheduler_or_agent(monkeypatch, capsys):
    mod = load_module()
    calls = []

    def fake_capture(**kwargs):
        calls.append(kwargs)
        return {"status": "RAW_CAPTURED_STRUCTURAL_ROWS_LOCAL_BOUNDARY_ONLY"}

    monkeypatch.setattr(mod, "capture_candles", fake_capture)
    result = mod.main(
        [
            "--interval", "15m",
            "--start-time-ms", "1000",
            "--end-time-ms", "2000",
            "--output-dir", "/tmp/capture",
            "--run-intent", "/tmp/intent.json",
            "--run-intent-sha256", "a" * 64,
        ]
    )

    assert result == 0
    assert len(calls) == 1
    assert calls[0]["run_intent_hash"] == "a" * 64
    assert json.loads(capsys.readouterr().out)["status"] == (
        "RAW_CAPTURED_STRUCTURAL_ROWS_LOCAL_BOUNDARY_ONLY"
    )
