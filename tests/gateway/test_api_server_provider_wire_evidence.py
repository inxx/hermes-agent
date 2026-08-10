import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agent.provider_wire_instrumentation import (
    PROVIDER_WIRE_EVIDENCE_HEADER,
    bind_provider_wire_recorder,
    instrument_httpx_transport,
    provider_wire_correlation_sha256,
    provider_wire_dispatch,
    provider_wire_request_target_sha256,
)
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter


API_KEY = "test-provider-wire-key-123456"
NONCE = "0123456789abcdef0123456789abcdef"
BODY = {
    "model": "hermes-agent",
    "messages": [{"role": "user", "content": "bounded request"}],
}


def _adapter(api_key=""):
    extra = {"key": api_key} if api_key else {}
    return APIServerAdapter(PlatformConfig(enabled=True, extra=extra))


def _app(adapter):
    app = web.Application()
    app.router.add_post("/v1/chat/completions", adapter._handle_chat_completions)
    return app


def _headers(nonce=NONCE):
    return {
        "Authorization": f"Bearer {API_KEY}",
        PROVIDER_WIRE_EVIDENCE_HEADER: nonce,
    }


def test_default_request_has_no_evidence_and_preserves_existing_shape():
    async def exercise():
        adapter = _adapter()
        result = {
            "final_response": "ok",
            "messages": [],
            "api_calls": 1,
        }
        usage = {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
        async with TestClient(TestServer(_app(adapter))) as client:
            with patch.object(adapter, "_run_agent", new_callable=AsyncMock) as run_agent:
                run_agent.return_value = (result, usage)
                response = await client.post("/v1/chat/completions", json=BODY)
                payload = await response.json()

        assert response.status == 200
        assert "hermes" not in payload
        assert "provider_wire_recorder" not in run_agent.call_args.kwargs

    asyncio.run(exercise())


def test_evidence_requires_a_configured_authenticated_gateway():
    async def exercise():
        adapter = _adapter()
        async with TestClient(TestServer(_app(adapter))) as client:
            response = await client.post(
                "/v1/chat/completions",
                json=BODY,
                headers={PROVIDER_WIRE_EVIDENCE_HEADER: NONCE},
            )
            payload = await response.json()
        assert response.status == 403
        assert payload["error"]["code"] == "provider_wire_evidence_auth_required"

    asyncio.run(exercise())


def test_evidence_header_with_invalid_bearer_never_reaches_agent():
    async def exercise():
        adapter = _adapter(API_KEY)
        async with TestClient(TestServer(_app(adapter))) as client:
            with patch.object(adapter, "_run_agent", new_callable=AsyncMock) as run_agent:
                response = await client.post(
                    "/v1/chat/completions",
                    json=BODY,
                    headers={
                        "Authorization": "Bearer wrong-key",
                        PROVIDER_WIRE_EVIDENCE_HEADER: NONCE,
                    },
                )
        assert response.status == 401
        run_agent.assert_not_awaited()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("nonce", "extra_body", "extra_headers", "expected_code"),
    [
        ("BAD", {}, {}, "provider_wire_evidence_invalid"),
        (NONCE, {"stream": True}, {}, "provider_wire_evidence_stream_unsupported"),
        (NONCE, {}, {"Idempotency-Key": "cached"}, "provider_wire_evidence_idempotency_forbidden"),
    ],
)
def test_invalid_or_replayable_evidence_requests_fail_before_agent_run(
    nonce, extra_body, extra_headers, expected_code
):
    async def exercise():
        adapter = _adapter(API_KEY)
        headers = {**_headers(nonce), **extra_headers}
        async with TestClient(TestServer(_app(adapter))) as client:
            with patch.object(adapter, "_run_agent", new_callable=AsyncMock) as run_agent:
                response = await client.post(
                    "/v1/chat/completions",
                    json={**BODY, **extra_body},
                    headers=headers,
                )
                payload = await response.json()
        assert response.status == 400
        assert payload["error"]["code"] == expected_code
        run_agent.assert_not_awaited()

    asyncio.run(exercise())


def test_authenticated_one_transport_exchange_returns_sanitized_exact_evidence():
    async def exercise():
        adapter = _adapter(API_KEY)
        provider_calls = 0

        async def fake_run_agent(**kwargs):
            nonlocal provider_calls
            recorder = kwargs["provider_wire_recorder"]

            def provider(_request):
                nonlocal provider_calls
                provider_calls += 1
                return httpx.Response(200, json={"choices": []})

            with bind_provider_wire_recorder(recorder):
                transport = instrument_httpx_transport(httpx.MockTransport(provider))
                with provider_wire_dispatch({"call_role": "primary"}):
                    with httpx.Client(transport=transport) as provider_client:
                        provider_client.post(
                            "http://127.0.0.1:8080/v1/chat/completions"
                        )

            return (
                {"final_response": "ok", "messages": [], "api_calls": 1},
                {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            )

        async with TestClient(TestServer(_app(adapter))) as client:
            with patch.object(adapter, "_run_agent", side_effect=fake_run_agent):
                response = await client.post(
                    "/v1/chat/completions", json=BODY, headers=_headers()
                )
                payload = await response.json()

        assert response.status == 200
        evidence = payload["hermes"]["provider_wire_evidence"]
        assert provider_calls == 1
        assert evidence == {
            "schema_version": "hermes.provider-wire-attempt-evidence.v1",
            "correlation_sha256": provider_wire_correlation_sha256(NONCE),
            "request_target_sha256": provider_wire_request_target_sha256(
                "POST", "http://127.0.0.1:8080/v1/chat/completions"
            ),
            "scope": "client_http_transport_attempt",
            "client_transport_status": "EXACT",
            "attempt_count": 1,
            "blocked_attempt_count": 0,
            "retry_count": 0,
            "fallback_count": 0,
            "completed_response_count": 1,
            "provider_receipt_status": "UNPROVEN",
        }
        serialized = json.dumps(evidence)
        assert NONCE not in serialized
        assert "bounded request" not in serialized
        assert "127.0.0.1" not in serialized

    asyncio.run(exercise())


def test_failed_run_can_only_return_unknown_sanitized_evidence():
    async def exercise():
        adapter = _adapter(API_KEY)

        async def fail_run(**kwargs):
            recorder = kwargs["provider_wire_recorder"]
            with bind_provider_wire_recorder(recorder):
                instrument_httpx_transport(
                    httpx.MockTransport(lambda request: httpx.Response(200))
                )
            raise RuntimeError("OPENAI_API_KEY=sk-never-return-this")

        async with TestClient(TestServer(_app(adapter))) as client:
            with patch.object(adapter, "_run_agent", side_effect=fail_run):
                response = await client.post(
                    "/v1/chat/completions", json=BODY, headers=_headers()
                )
                payload = await response.json()

        assert response.status == 500
        assert "sk-never-return-this" not in json.dumps(payload)
        evidence = payload["error"]["hermes"]["provider_wire_evidence"]
        assert evidence["client_transport_status"] == "UNKNOWN"
        assert "sk-never-return-this" not in json.dumps(evidence)

    asyncio.run(exercise())
