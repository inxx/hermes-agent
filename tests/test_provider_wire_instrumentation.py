import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest

from agent import relay_llm
from agent.agent_runtime_helpers import create_openai_client
from agent.chat_completion_helpers import _context_thread_target
from agent.provider_wire_instrumentation import (
    PROVIDER_RECEIPT_STATUS,
    PROVIDER_WIRE_EVIDENCE_SCHEMA,
    PROVIDER_WIRE_EVIDENCE_SCOPE,
    ProviderWireEvidenceError,
    ProviderWireLimitError,
    ProviderWireRecorder,
    bind_provider_wire_recorder,
    current_provider_wire_recorder,
    instrument_async_httpx_transport,
    instrument_httpx_transport,
    provider_wire_correlation_sha256,
    provider_wire_dispatch,
    provider_wire_request_target_sha256,
    sanitized_provider_wire_evidence,
)


NONCE = "0123456789abcdef0123456789abcdef"


def _success_evidence(recorder):
    return sanitized_provider_wire_evidence(recorder, terminal_success=True)


def test_nonce_is_strict_and_only_its_digest_is_exposed():
    recorder = ProviderWireRecorder(NONCE)
    evidence = _success_evidence(recorder)

    assert evidence["correlation_sha256"] == provider_wire_correlation_sha256(NONCE)
    assert NONCE not in repr(evidence)
    assert evidence["schema_version"] == PROVIDER_WIRE_EVIDENCE_SCHEMA
    assert evidence["scope"] == PROVIDER_WIRE_EVIDENCE_SCOPE
    assert evidence["provider_receipt_status"] == PROVIDER_RECEIPT_STATUS
    assert set(evidence) == {
        "schema_version",
        "correlation_sha256",
        "request_target_sha256",
        "scope",
        "client_transport_status",
        "attempt_count",
        "blocked_attempt_count",
        "retry_count",
        "fallback_count",
        "completed_response_count",
        "provider_receipt_status",
    }

    for invalid in ("", "A" * 32, "0" * 31, "0" * 33, "g" * 32, None):
        with pytest.raises(ProviderWireEvidenceError):
            ProviderWireRecorder(invalid)

    with pytest.raises(
        ProviderWireEvidenceError,
        match="provider_wire_request_target_invalid",
    ):
        provider_wire_request_target_sha256(
            "POST",
            "http://127.0.0.1:8080/v1/chat/completions?secret=value",
        )


def test_instrumentation_is_inert_without_an_explicit_scope():
    transport = httpx.MockTransport(lambda request: httpx.Response(200))
    assert instrument_httpx_transport(transport) is transport
    assert sanitized_provider_wire_evidence(None, terminal_success=True) is None


def test_caller_supplied_http_client_is_rejected_before_provider_execution():
    recorder = ProviderWireRecorder(NONCE)
    agent = SimpleNamespace(provider="custom")

    with bind_provider_wire_recorder(recorder):
        with pytest.raises(
            ProviderWireEvidenceError,
            match="provider_wire_custom_http_client_unsupported",
        ):
            create_openai_client(
                agent,
                {"http_client": object()},
                reason="owner_one_shot",
                shared=False,
            )

    assert _success_evidence(recorder)["attempt_count"] == 0


def test_real_agent_constructor_registers_owned_transport_without_provider_io(
    tmp_path,
    monkeypatch,
):
    from run_agent import AIAgent

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    recorder = ProviderWireRecorder(NONCE)
    with bind_provider_wire_recorder(recorder):
        agent = AIAgent(
            provider="custom",
            model="hermes-agent",
            base_url="http://127.0.0.1:8080/v1",
            api_key="test-only",
            enabled_toolsets=[],
            skip_context_files=True,
            skip_memory=True,
            session_db=None,
            fallback_model=None,
            max_iterations=1,
            quiet_mode=True,
        )
        try:
            recorder.require_registered_transport()
        finally:
            agent.close()

    evidence = sanitized_provider_wire_evidence(
        recorder,
        terminal_success=False,
    )
    assert evidence["attempt_count"] == 0
    assert evidence["completed_response_count"] == 0
    assert evidence["client_transport_status"] == "UNKNOWN"


def test_one_relay_dispatch_and_one_transport_response_is_exact():
    recorder = ProviderWireRecorder(NONCE)
    calls = []
    inner = httpx.MockTransport(
        lambda request: calls.append((request.method, request.url.path))
        or httpx.Response(200, json={"ok": True})
    )

    with bind_provider_wire_recorder(recorder):
        transport = instrument_httpx_transport(inner)

        def callback(_request):
            with httpx.Client(transport=transport) as client:
                return client.post("http://127.0.0.1:8080/v1/chat/completions")

        response = relay_llm.execute_current(
            {},
            callback,
            name="local",
            model_name="local-model",
            metadata={"api_request_id": "request-1", "call_role": "primary"},
        )

    assert response.status_code == 200
    assert calls == [("POST", "/v1/chat/completions")]
    assert _success_evidence(recorder) == {
        "schema_version": PROVIDER_WIRE_EVIDENCE_SCHEMA,
        "correlation_sha256": provider_wire_correlation_sha256(NONCE),
        "request_target_sha256": provider_wire_request_target_sha256(
            "POST", "http://127.0.0.1:8080/v1/chat/completions"
        ),
        "scope": PROVIDER_WIRE_EVIDENCE_SCOPE,
        "client_transport_status": "EXACT",
        "attempt_count": 1,
        "blocked_attempt_count": 0,
        "retry_count": 0,
        "fallback_count": 0,
        "completed_response_count": 1,
        "provider_receipt_status": "UNPROVEN",
    }


def test_second_transport_attempt_is_blocked_before_inner_transport():
    recorder = ProviderWireRecorder(NONCE)
    calls = 0

    def respond(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    with bind_provider_wire_recorder(recorder):
        transport = instrument_httpx_transport(httpx.MockTransport(respond))
        with provider_wire_dispatch({"call_role": "primary"}):
            with httpx.Client(transport=transport) as client:
                assert client.post("http://127.0.0.1:8080/v1/chat/completions").status_code == 200
                with pytest.raises(ProviderWireLimitError):
                    client.post("http://127.0.0.1:8080/v1/chat/completions")

    evidence = _success_evidence(recorder)
    assert calls == 1
    assert evidence["attempt_count"] == 1
    assert evidence["blocked_attempt_count"] == 1
    assert evidence["retry_count"] == 1
    assert evidence["client_transport_status"] == "UNKNOWN"


def test_second_relay_dispatch_is_blocked_and_fallback_is_distinct():
    recorder = ProviderWireRecorder(NONCE)
    inner = httpx.MockTransport(lambda request: httpx.Response(200))
    with bind_provider_wire_recorder(recorder):
        transport = instrument_httpx_transport(inner)
        with provider_wire_dispatch({"call_role": "primary"}):
            with httpx.Client(transport=transport) as client:
                client.post("http://127.0.0.1:8080/v1/chat/completions")
        with pytest.raises(ProviderWireLimitError):
            with provider_wire_dispatch({"call_role": "fallback"}):
                raise AssertionError("fallback body must not execute")

    evidence = _success_evidence(recorder)
    assert evidence["attempt_count"] == 1
    assert evidence["blocked_attempt_count"] == 1
    assert evidence["fallback_count"] == 1
    assert evidence["retry_count"] == 0
    assert evidence["client_transport_status"] == "UNKNOWN"


def test_unmatched_auxiliary_attempt_blocks_later_primary_dispatch():
    recorder = ProviderWireRecorder(NONCE)
    calls = 0

    def respond(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    with bind_provider_wire_recorder(recorder):
        transport = instrument_httpx_transport(
            httpx.MockTransport(respond),
            transport_role="auxiliary",
        )
        with httpx.Client(transport=transport) as client:
            client.post("http://127.0.0.1:8080/v1/chat/completions")
        with pytest.raises(ProviderWireLimitError):
            with provider_wire_dispatch({"call_role": "primary"}):
                raise AssertionError("primary body must not execute")

    evidence = _success_evidence(recorder)
    assert calls == 1
    assert evidence["attempt_count"] == 1
    assert evidence["blocked_attempt_count"] == 1
    assert evidence["client_transport_status"] == "UNKNOWN"


def test_dispatch_without_wrapped_transport_is_unknown():
    recorder = ProviderWireRecorder(NONCE)
    with bind_provider_wire_recorder(recorder):
        with provider_wire_dispatch({"call_role": "primary"}):
            pass
        with pytest.raises(ProviderWireLimitError):
            with provider_wire_dispatch({"call_role": "primary"}):
                raise AssertionError("second unmatched dispatch must not execute")
    evidence = _success_evidence(recorder)
    assert evidence["blocked_attempt_count"] == 1
    assert evidence["retry_count"] == 1
    assert evidence["client_transport_status"] == "UNKNOWN"


def test_recorder_is_request_local_across_threads():
    seen = []
    first = ProviderWireRecorder(NONCE)
    second = ProviderWireRecorder("fedcba9876543210fedcba9876543210")

    def run(recorder):
        with bind_provider_wire_recorder(recorder):
            transport = instrument_httpx_transport(
                httpx.MockTransport(lambda request: httpx.Response(200))
            )
            with provider_wire_dispatch({"call_role": "primary"}):
                with httpx.Client(transport=transport) as client:
                    client.post("http://127.0.0.1:8080/v1/chat/completions")
        seen.append(_success_evidence(recorder))

    threads = [threading.Thread(target=run, args=(recorder,)) for recorder in (first, second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(seen) == 2
    assert {item["correlation_sha256"] for item in seen} == {
        provider_wire_correlation_sha256(NONCE),
        provider_wire_correlation_sha256("fedcba9876543210fedcba9876543210"),
    }
    assert all(item["client_transport_status"] == "EXACT" for item in seen)


def test_interrupt_worker_target_copies_the_request_evidence_context():
    recorder = ProviderWireRecorder(NONCE)
    seen = []

    with bind_provider_wire_recorder(recorder):
        target = _context_thread_target(
            lambda: seen.append(
                sanitized_provider_wire_evidence(
                    current_provider_wire_recorder(),
                    terminal_success=False,
                )["correlation_sha256"]
            )
        )
    worker = threading.Thread(target=target)
    worker.start()
    worker.join()

    assert seen == [provider_wire_correlation_sha256(NONCE)]


def test_recorder_bound_request_clients_are_never_put_in_the_warm_cache():
    from run_agent import AIAgent

    agent = AIAgent.__new__(AIAgent)
    agent.provider = "custom"
    agent._client_kwargs = {
        "api_key": "test",
        "base_url": "http://127.0.0.1:8080/v1",
    }
    agent._ensure_primary_openai_client = MagicMock(return_value=object())
    first_client = SimpleNamespace(name="first")
    second_client = SimpleNamespace(name="second")
    agent._create_openai_client = MagicMock(
        side_effect=(first_client, second_client)
    )
    agent._close_openai_client = MagicMock()

    with bind_provider_wire_recorder(ProviderWireRecorder(NONCE)):
        first = agent._create_request_openai_client(reason="owner_one_shot")
        agent._close_request_openai_client(first, reason="request_complete")
    with bind_provider_wire_recorder(
        ProviderWireRecorder("fedcba9876543210fedcba9876543210")
    ):
        second = agent._create_request_openai_client(reason="owner_one_shot")
        agent._close_request_openai_client(second, reason="request_complete")

    assert first is first_client
    assert second is second_client
    assert agent._create_openai_client.call_count == 2
    assert agent._request_client_cache["client"] is None
    assert agent._close_openai_client.call_count == 2


def test_async_transport_has_the_same_one_attempt_boundary():
    recorder = ProviderWireRecorder(NONCE)
    calls = 0

    async def respond(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    async def exercise():
        with bind_provider_wire_recorder(recorder):
            transport = instrument_async_httpx_transport(httpx.MockTransport(respond))
            with provider_wire_dispatch({"call_role": "primary"}):
                async with httpx.AsyncClient(transport=transport) as client:
                    response = await client.post(
                        "http://127.0.0.1:8080/v1/chat/completions"
                    )
                    assert response.status_code == 200
                    with pytest.raises(ProviderWireLimitError):
                        await client.post(
                            "http://127.0.0.1:8080/v1/chat/completions"
                        )

    asyncio.run(exercise())
    assert calls == 1
    assert _success_evidence(recorder)["client_transport_status"] == "UNKNOWN"
