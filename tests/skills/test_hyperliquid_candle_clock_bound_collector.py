from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "optional-skills/blockchain/hyperliquid/scripts/candle_clock_bound_collector.py"
spec = importlib.util.spec_from_file_location("candle_clock_bound_collector", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def contract(tmp_path: Path, slots: list[int]) -> tuple[dict, Path, str]:
    home = tmp_path / "home"
    scripts = home / "scripts"
    scripts.mkdir(parents=True)
    collector = scripts / "collector.py"
    collector.write_bytes(SCRIPT.read_bytes())
    adapter = scripts / "adapter.py"
    adapter.write_text("SOURCE_CONTRACT_SHA256 = '" + "a" * 64 + "'\n")
    value = {
        "schema_version": module.CONTRACT_SCHEMA,
        "status": module.CONTRACT_STATUS,
        "stream_id": "hyperliquid-btc-15m-clock-bound-raw-v1",
        "endpoint": module.ENDPOINT,
        "coin": "BTC",
        "interval": "15m",
        "period_ms": module.PERIOD_MS,
        "authorized_slot_end_ms": slots,
        "minimum_delay_ms": 60_000,
        "maximum_delay_ms": 240_000,
        "maximum_http_requests_per_slot": 1,
        "automatic_retries": 0,
        "redirects": 0,
        "proxy_url": "http://127.0.0.1:28990",
        "collector_path": str(collector),
        "collector_sha256": sha(collector),
        "adapter_path": str(adapter),
        "adapter_sha256": sha(adapter),
        "source_contract_sha256": "a" * 64,
        "intents_root": str(home / "candle-run-intents"),
        "acquisitions_root": str(home / "acquisitions"),
        "capabilities": module.CAPABILITIES,
    }
    path = home / "collector-contracts" / "contract.json"
    path.parent.mkdir()
    raw = module.canonical_bytes(value) + b"\n"
    path.write_bytes(raw)
    return value, path, hashlib.sha256(raw).hexdigest()


def test_contract_and_slot_are_exact_and_bounded(tmp_path):
    slot = 1_800_000
    value, path, digest = contract(tmp_path, [slot, slot + module.PERIOD_MS])
    loaded = module.load_contract(
        path,
        expected_sha256=digest,
        hermes_home=tmp_path / "home",
        collector_path=Path(value["collector_path"]),
    )
    assert module.select_slot(loaded, slot + 60_000) == slot
    assert module.select_slot(loaded, slot + 240_001) is None


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(capabilities={**module.CAPABILITIES, "strategy_evaluation": True}),
    lambda value: value.update(proxy_url="http://127.0.0.1:9999"),
    lambda value: value.update(automatic_retries=1),
    lambda value: value.update(authorized_slot_end_ms=[1_800_000, 3_600_000]),
])
def test_contract_rejects_policy_mutation(tmp_path, mutation):
    value, path, _ = contract(tmp_path, [1_800_000, 2_700_000])
    mutation(value)
    raw = module.canonical_bytes(value) + b"\n"
    path.write_bytes(raw)
    with pytest.raises(module.ClockBoundCollectorError):
        module.load_contract(
            path,
            expected_sha256=hashlib.sha256(raw).hexdigest(),
            hermes_home=tmp_path / "home",
            collector_path=Path(value["collector_path"]),
        )


def test_one_due_slot_creates_one_exact_intent_and_calls_adapter_once(tmp_path):
    slot = 1_800_000
    value, _, _ = contract(tmp_path, [slot])
    calls = []

    def fake_capture(**kwargs):
        calls.append(kwargs)
        output = Path(kwargs["output_dir"])
        output.mkdir(mode=0o700, parents=True)
        (output / "receipt.json").write_text("{}\n")
        return {"completed_row_count": 1}

    result = module.run_once(value, now_ms=slot + 60_000, capture_fn=fake_capture)
    assert result["status"] == "CLOCK_BOUND_RAW_CAPTURE_COMPLETED"
    assert len(calls) == 1
    intent = json.loads(Path(calls[0]["run_intent"]).read_text())
    assert intent["request"]["req"] == {
        "coin": "BTC",
        "interval": "15m",
        "startTime": slot - module.PERIOD_MS,
        "endTime": slot,
    }
    assert intent["maximum_http_requests"] == 1
    assert intent["retries"] == 0
    assert set(intent["authorities"].values()) == {False}
    assert module.run_once(value, now_ms=slot + 120_000, capture_fn=fake_capture)["status"] == "SLOT_ALREADY_CAPTURED"
    assert len(calls) == 1


def test_existing_partial_namespace_fails_without_retry(tmp_path):
    slot = 1_800_000
    value, _, _ = contract(tmp_path, [slot])
    run_id = "hyperliquid-candle-btc-15m-clock-19700101T003000Z"
    intent = Path(value["intents_root"]) / run_id / "run-intent.json"
    intent.parent.mkdir(parents=True)
    intent.write_text("{}\n")
    with pytest.raises(module.ClockBoundCollectorError, match="slot_namespace_exists"):
        module.run_once(value, now_ms=slot + 60_000, capture_fn=lambda **_: {})


def test_outside_authorized_window_is_silent_and_does_not_write(tmp_path):
    value, _, _ = contract(tmp_path, [1_800_000])
    assert module.run_once(value, now_ms=2_100_001)["status"] == "NO_AUTHORIZED_SLOT_DUE"
    assert not Path(value["intents_root"]).exists()
