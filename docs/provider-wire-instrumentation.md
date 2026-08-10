# Provider client-transport attempt evidence

Hermes can expose narrowly scoped, request-local evidence for an owner-reviewed
non-streaming `POST /v1/chat/completions`. The feature is off by default. It is
enabled only when an authenticated request includes
`X-Hermes-Provider-Wire-Evidence: <nonce>`, where `<nonce>` is exactly 32
lowercase hexadecimal characters.

The evidence claim is deliberately limited to `client_http_transport_attempt`:
Hermes observed exactly one call into its instrumented HTTPX client transport
and one returned HTTP response. It is not provider-side telemetry, and
`provider_receipt_status` therefore remains `UNPROVEN` even when the client
transport evidence `client_transport_status` is `EXACT`. This field is not a
provider receipt and must never be interpreted as one.

## Fail-closed contract

Evidence mode:

- requires a configured API key and successful gateway authentication;
- supports only non-streaming requests and rejects `Idempotency-Key`;
- admits at most one semantic provider dispatch and at most one HTTP transport
  attempt, rejecting a retry or fallback before its callback or transport is
  invoked;
- configures the owned HTTPX transports with SDK transport retries disabled;
- requires the request's agent to construct a registered, instrumented
  transport before conversation execution begins; and
- reports `EXACT` only after a successful terminal agent result with one
  matched transport attempt and response, and zero blocked attempts, retries,
  fallbacks, unmatched dispatches, or unmatched transports.

Proxy-backed transports, caller-supplied/custom clients, and provider paths
that do not use the owned HTTPX transport cannot satisfy this proof. They fail
before conversation execution with `UNKNOWN` evidence instead of weakening the
claim.

## Evidence and privacy

The response adds `hermes.provider_wire_evidence` only for an opted-in request.
The object contains domain-separated SHA-256 correlation and outbound
method/origin/path digests, the fixed scope and provider-receipt status, and
integer counters. The owner-side caller must bind both digests to its approved
plan and expected loopback target. The inbound nonce is not echoed or forwarded
to the provider. The recorder retains no prompt,
request or response body, URL, headers, credentials, model output, or raw
exception text. It writes no database or file, emits no telemetry, and does not
alter prompt construction or prompt caching.

Without the opt-in header, transport wrapping is inert and the gateway response
shape and existing retry behavior are unchanged.
