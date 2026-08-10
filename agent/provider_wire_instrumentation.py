"""Request-scoped evidence for bounded provider HTTP transport attempts.

This module is inert unless an authenticated API request explicitly binds a
``ProviderWireRecorder``.  It retains only counters and domain-separated
digests.  Prompt text, request/response bodies, headers, URLs, credentials,
model output, and raw exceptions are never retained.

The exact claim is deliberately narrow: a recorded attempt is one call into a
client HTTP transport, immediately before the inner transport is invoked.  It
is not provider-side telemetry and does not prove what a provider did after it
received the HTTP exchange.
"""

from __future__ import annotations

import hashlib
import re
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Iterator, Mapping
from urllib.parse import urlsplit


PROVIDER_WIRE_EVIDENCE_HEADER = "X-Hermes-Provider-Wire-Evidence"
PROVIDER_WIRE_EVIDENCE_SCHEMA = "hermes.provider-wire-attempt-evidence.v1"
PROVIDER_WIRE_EVIDENCE_SCOPE = "client_http_transport_attempt"
PROVIDER_RECEIPT_STATUS = "UNPROVEN"

_NONCE = re.compile(r"^[0-9a-f]{32}$")
_DOMAIN = b"hermes.provider-wire-attempt-evidence.correlation.v1\n"
_TARGET_DOMAIN = b"hermes.provider-wire-attempt-evidence.target.v1\n"
_CURRENT_RECORDER: ContextVar["ProviderWireRecorder | None"] = ContextVar(
    "provider_wire_recorder", default=None
)
_CURRENT_DISPATCH: ContextVar["_Dispatch | None"] = ContextVar(
    "provider_wire_dispatch", default=None
)


class ProviderWireEvidenceError(ValueError):
    """Fixed-code validation error safe to return at the API boundary."""


class ProviderWireLimitError(RuntimeError):
    """Raised before a second provider transport attempt is dispatched."""

    def __init__(self) -> None:
        super().__init__("provider_wire_attempt_budget_exceeded")


@dataclass(frozen=True)
class _Dispatch:
    dispatch_id: int
    role: str
    transport_attempts_at_start: int


def validate_provider_wire_nonce(value: Any) -> str:
    nonce = str(value or "")
    if not _NONCE.fullmatch(nonce):
        raise ProviderWireEvidenceError("provider_wire_evidence_nonce_invalid")
    return nonce


def provider_wire_correlation_sha256(nonce: str) -> str:
    valid = validate_provider_wire_nonce(nonce)
    return hashlib.sha256(_DOMAIN + valid.encode("ascii")).hexdigest()


def provider_wire_request_target_sha256(method: Any, url: Any) -> str:
    """Digest the outbound method/origin/path without retaining the raw URL."""
    verb = str(method or "").strip().upper()
    parsed = urlsplit(str(url or ""))
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if (
        not verb
        or scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
    ):
        raise ProviderWireEvidenceError("provider_wire_request_target_invalid")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProviderWireEvidenceError(
            "provider_wire_request_target_invalid"
        ) from exc
    if port is None:
        port = 443 if scheme == "https" else 80
    path = parsed.path or "/"
    canonical = f"{verb}\n{scheme}://{host}:{port}{path}".encode("utf-8")
    return hashlib.sha256(_TARGET_DOMAIN + canonical).hexdigest()


class ProviderWireRecorder:
    """Thread-safe, request-local recorder with a hard one-attempt budget."""

    def __init__(self, nonce: str, *, max_transport_attempts: int = 1) -> None:
        if max_transport_attempts != 1:
            raise ProviderWireEvidenceError("provider_wire_attempt_budget_invalid")
        self._correlation_sha256 = provider_wire_correlation_sha256(nonce)
        self._max_transport_attempts = max_transport_attempts
        self._lock = threading.RLock()
        self._transport_registered = False
        self._primary_transport_registered = False
        self._request_target_sha256 = ""
        self._transport_attempt_count = 0
        self._completed_response_count = 0
        self._blocked_attempt_count = 0
        self._retry_count = 0
        self._fallback_count = 0
        self._dispatch_count = 0
        self._active_dispatch_count = 0
        self._unmatched_dispatch_count = 0
        self._unmatched_transport_count = 0

    def register_transport(self, *, transport_role: str) -> None:
        with self._lock:
            self._transport_registered = True
            if transport_role == "primary":
                self._primary_transport_registered = True

    def require_registered_transport(self) -> None:
        with self._lock:
            if not self._primary_transport_registered:
                raise ProviderWireEvidenceError(
                    "provider_wire_exact_transport_unavailable"
                )

    def begin_dispatch(self, metadata: Mapping[str, Any] | None = None) -> _Dispatch:
        role = str((metadata or {}).get("call_role") or "primary")
        with self._lock:
            self._dispatch_count += 1
            dispatch = _Dispatch(
                dispatch_id=self._dispatch_count,
                role=role,
                transport_attempts_at_start=self._transport_attempt_count,
            )
            if role == "fallback":
                self._fallback_count += 1
            # The semantic dispatch boundary is the broadest provider-call
            # chokepoint.  Block a second dispatch even when the first used an
            # unsupported transport and therefore produced no matched HTTPX
            # event; otherwise an uninstrumented first attempt could be
            # followed by a real second provider call before evidence falls
            # back to UNKNOWN.
            if (
                self._dispatch_count > self._max_transport_attempts
                or self._transport_attempt_count >= self._max_transport_attempts
            ):
                self._blocked_attempt_count += 1
                if role != "fallback":
                    self._retry_count += 1
                raise ProviderWireLimitError()
            self._active_dispatch_count += 1
            return dispatch

    def finish_dispatch(self, dispatch: _Dispatch) -> None:
        with self._lock:
            self._active_dispatch_count = max(0, self._active_dispatch_count - 1)
            if self._transport_attempt_count == dispatch.transport_attempts_at_start:
                self._unmatched_dispatch_count += 1

    def record_transport_attempt(
        self,
        dispatch: _Dispatch | None,
        *,
        request_target_sha256: str,
    ) -> None:
        with self._lock:
            if self._transport_attempt_count >= self._max_transport_attempts:
                self._blocked_attempt_count += 1
                self._retry_count += 1
                raise ProviderWireLimitError()
            self._transport_attempt_count += 1
            self._request_target_sha256 = request_target_sha256
            if dispatch is None:
                self._unmatched_transport_count += 1

    def record_completed_response(self) -> None:
        with self._lock:
            self._completed_response_count += 1

    def evidence(self, *, terminal_success: bool) -> dict[str, Any]:
        with self._lock:
            exact = (
                terminal_success
                and self._primary_transport_registered
                and self._transport_attempt_count == 1
                and bool(self._request_target_sha256)
                and self._completed_response_count == 1
                and self._blocked_attempt_count == 0
                and self._retry_count == 0
                and self._fallback_count == 0
                and self._unmatched_dispatch_count == 0
                and self._unmatched_transport_count == 0
                and self._active_dispatch_count == 0
            )
            return {
                "schema_version": PROVIDER_WIRE_EVIDENCE_SCHEMA,
                "correlation_sha256": self._correlation_sha256,
                "request_target_sha256": self._request_target_sha256,
                "scope": PROVIDER_WIRE_EVIDENCE_SCOPE,
                "client_transport_status": "EXACT" if exact else "UNKNOWN",
                "attempt_count": self._transport_attempt_count,
                "blocked_attempt_count": self._blocked_attempt_count,
                "retry_count": self._retry_count,
                "fallback_count": self._fallback_count,
                "completed_response_count": self._completed_response_count,
                "provider_receipt_status": PROVIDER_RECEIPT_STATUS,
            }


@contextmanager
def bind_provider_wire_recorder(
    recorder: ProviderWireRecorder | None,
) -> Iterator[ProviderWireRecorder | None]:
    token = _CURRENT_RECORDER.set(recorder)
    try:
        yield recorder
    finally:
        _CURRENT_RECORDER.reset(token)


def current_provider_wire_recorder() -> ProviderWireRecorder | None:
    return _CURRENT_RECORDER.get()


@contextmanager
def provider_wire_dispatch(
    metadata: Mapping[str, Any] | None = None,
) -> Iterator[None]:
    recorder = current_provider_wire_recorder()
    if recorder is None:
        yield
        return
    dispatch = recorder.begin_dispatch(metadata)
    token = _CURRENT_DISPATCH.set(dispatch)
    try:
        yield
    finally:
        _CURRENT_DISPATCH.reset(token)
        recorder.finish_dispatch(dispatch)


def sanitized_provider_wire_evidence(
    recorder: ProviderWireRecorder | None,
    *,
    terminal_success: bool,
) -> dict[str, Any] | None:
    if recorder is None:
        return None
    return recorder.evidence(terminal_success=terminal_success)


def instrument_httpx_transport(
    transport: Any,
    recorder: ProviderWireRecorder | None = None,
    *,
    transport_role: str = "primary",
) -> Any:
    """Wrap a synchronous HTTPX transport when an evidence scope is active."""
    active = recorder or current_provider_wire_recorder()
    if active is None:
        return transport

    import httpx

    active.register_transport(transport_role=transport_role)

    class _InstrumentedTransport(httpx.BaseTransport):
        def handle_request(self, request):
            active.record_transport_attempt(
                _CURRENT_DISPATCH.get(),
                request_target_sha256=provider_wire_request_target_sha256(
                    request.method,
                    request.url,
                ),
            )
            response = transport.handle_request(request)
            active.record_completed_response()
            return response

        def close(self):
            return transport.close()

    return _InstrumentedTransport()


def instrument_async_httpx_transport(
    transport: Any,
    recorder: ProviderWireRecorder | None = None,
    *,
    transport_role: str = "primary",
) -> Any:
    """Wrap an asynchronous HTTPX transport when an evidence scope is active."""
    active = recorder or current_provider_wire_recorder()
    if active is None:
        return transport

    import httpx

    active.register_transport(transport_role=transport_role)

    class _InstrumentedAsyncTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            active.record_transport_attempt(
                _CURRENT_DISPATCH.get(),
                request_target_sha256=provider_wire_request_target_sha256(
                    request.method,
                    request.url,
                ),
            )
            response = await transport.handle_async_request(request)
            active.record_completed_response()
            return response

        async def aclose(self):
            return await transport.aclose()

    return _InstrumentedAsyncTransport()
