# Certificate Revocation (Producer)

**Repository:** `federator`  
**Description:** `OCSP revocation checks of consumer client certificates on the producer`

<!-- SPDX-License-Identifier: OGL-UK-3.0 -->

---

## Overview

With mTLS enabled, the producer (Federator server) checks that a consumer's client certificate has not been revoked:

1. **TLS handshake.** After the chain validates against `server.truststoreFilePath`, the consumer's certificate is checked. A revoked or unknown certificate fails the handshake.
2. **Each new gRPC call.** Before JWT validation, consumer authorisation and OPA, the certificate is checked again, normally from the cache. A revoked or unknown certificate closes the call with `UNAUTHENTICATED`.
3. **During communication.** For every consumer with open calls, the status is checked again as soon as its cache entry expires. If the certificate is revoked or unknown, all of that consumer's calls are closed with `UNAUTHENTICATED`. Calls of other consumers are not affected.

A revoked consumer can therefore keep an open call for at most `revocation.cache.ttl.seconds`, plus the time of one OCSP check (at most `revocation.ocsp.requestTimeout × revocation.ocsp.resilience.retry.maxAttempts`, 4 s by default). The Management Node answers OCSP from Vault without caching, so a revocation is visible to the next check right away.

| Status | Handshake | New call | Open calls at re-check |
|---|---|---|---|
| `good` | accepted | proceeds | continue |
| `revoked` | fails | `UNAUTHENTICATED` | all closed with `UNAUTHENTICATED` |
| `unknown` | fails | `UNAUTHENTICATED` | all closed with `UNAUTHENTICATED` |
| No valid status (responder unreachable, circuit open, invalid response) and no valid cache entry | fails | `UNAVAILABLE` | all closed with `UNAVAILABLE` |

The last row applies with `revocation.enforcement.failClosed=true` (default). With `false`, the consumer is let through and a WARN is logged.

## Enablement

| `server.mtlsEnabled` | `revocation.enforcement.enabled` | Revocation checks |
|---|---|---|
| `true` | `true` (default) | applied |
| `true` | `false` | not applied, WARN at startup |
| `false` | any | not applied (no client certificates), WARN at startup |

An invalid revocation setting, for example `revocation.cache.ttl.seconds` above 600, stops the server at startup.

## Management Node OCSP API

The producer calls `POST ${management.node.base.url}${revocation.ocsp.path}` (default path `/api/v1/certificate/ocsp`) with a DER `OCSPRequest`:

- **Identity:** the existing Management Node HTTP client, so mTLS uses `idp.keystore.*` (the `idp.*` properties of `server.properties`).
- **Authorisation:** a bearer token from the IdP. The federator's client needs the `check_certificate_status` client role on the `management-node` client. Without it the Management Node answers HTTP 403, every check fails, and the federator logs `cause=unavailable` with `detail="unauthorized: ..."`.
- **Token:** the token is obtained within the time budget of the check and kept until shortly before it expires. The `management.node.resilience.*` retry (minutes of backoff) is not used for OCSP. A token request to the IdP times out after 30 s; one that still hangs after 35 s is abandoned and the next check starts a new one.

### Response verification

A response is used only when all of these hold. Otherwise it counts as a responder failure and is never cached.

- The response status is `successful`. `tryLater` and `internalError` are retried; `malformedRequest` and `unauthorized` are not.
- It is signed either by the CA that issued the consumer's certificate or by a delegated signer certificate that this CA issued. The signer must be valid now, carry the `id-kp-OCSPSigning` EKU, and allow `digitalSignature`. The signer's own revocation status is not checked (its lifetime is short).
- The nonce matches the request (`revocation.ocsp.requireNonce=true`).
- A single response answers exactly the requested certificate ID.
- `thisUpdate` is not in the future and `nextUpdate` is not in the past (30 s clock skew).

**Transitional signer setting.** Until the Management Node issues its signer through a dedicated Vault role, its signer certificate has no `id-kp-OCSPSigning` EKU. With `revocation.ocsp.requireSignerEku=false`, a delegated signer without the EKU is accepted only when its common name equals `revocation.ocsp.signerCommonName` (default `ocsp-signer.management-node`), and a WARN is logged for every new signer. This setting is refused at startup unless the OCSP URL is `https`: without the EKU any federation certificate with that common name could sign responses, so the Management Node must be authenticated by TLS. Check that the Management Node does not issue node certificates with that common name. Set it back to `true` once the dedicated role is deployed.

## Cache

- Key `issuerKeyHash:serial` (lowercase hex, the same format the Management Node uses). The value is `{status, thisUpdate, nextUpdate, cachedAt}`.
- An entry lives until the earlier of `cachedAt + revocation.cache.ttl.seconds` and the response's `nextUpdate`.
- `good`, `revoked` and `unknown` are cached. Failures are not.
- `revocation.cache.type=memory`: per instance, bounded by `revocation.cache.maxEntries`.
- `revocation.cache.type=redis`: shared by all producer instances through the existing `redis.*` connection. Keys are `${redis.prefix}:cert-status:<issuerKeyHash>:<serial>`, stored as plain JSON (`redis.aes.key` is not applied because a status is not secret) with a Redis TTL. A Redis failure is treated as a cache miss.

## Connections

grpc-java has no public API to close a single connection on the server, so on revocation the producer:

- closes every call of the certificate (the streaming loop stops and no further data is sent);
- invalidates the TLS session, so it cannot be resumed;
- rejects every new call on any remaining connection (the cache now holds `revoked`), and every new handshake;
- closes the connection once it has had no call for `server.maxConnectionIdle.seconds` (default 60 while revocation checks are active). The consumer federator closes its channel itself when its job fails, so this matters for a client that keeps its connection open.

A client that keeps sending calls is still disconnected by `server.maxConnectionAge.seconds` (default 1800 while revocation checks are active): it sends GOAWAY, after which no new call is accepted on that connection, and the rejected calls end at once. For good consumers it means new calls go over a new connection with a full handshake. Calls already running are not cut (`server.maxConnectionAgeGrace.seconds` is not set by default), because the re-check closes the calls of a revoked consumer anyway; setting the grace ends every long stream of good consumers too. A running stream is not idle, so `maxConnectionIdle` does not affect good consumers either. `server.tlsSessionTimeout.seconds` (default 300) limits TLS session resumption.

The OCSP query in the handshake blocks. The server uses the JDK SSL provider, so Netty runs certificate validation as a delegated task on the gRPC server executor rather than on the event loop.

## Failure mode

Fail-closed has a cost: if the Management Node or Vault is unavailable for longer than the cache TTL, consumers are disconnected and cannot reconnect until the OCSP API is back. Every such decision is logged at ERROR with the `SECURITY_ALERT` marker and ends with `alert=SECURITY_ALERT`, so it can be alerted on with any log pattern. In an emergency, `revocation.enforcement.enabled=false` (restart required) turns the checks off.

## Logging and metrics

Every decision is logged by the `RevocationAudit` logger as key=value:

```
event=revocation.decision component=producer phase=recheck peer_serial=4a1f issuer="O=Org,CN=Federation CA" status=revoked result=close cause=revoked connection_id=/10.0.0.5:51234/1a2b3c4d detail="2 call(s) closed; ocsp"
```

`phase` is `handshake`, `call` or `recheck`; `result` is `allow`, `reject` or `close`. `connection_id` is `<remote address>/<first 8 bytes of the TLS session id>`. The gRPC server does not know the remote address during the TLS handshake, so handshake lines show `-/<session id>`; the call and re-check lines of the same connection end with the same session id.

Metrics are served in Prometheus format at `GET http://<host>:${metrics.port}/metrics` (`metrics.enabled=true`, port `9464` by default):

| Metric | Tags |
|---|---|
| `federator_revocation_checks_total` | `role`, `phase`, `result`, `cause` |
| `federator_calls_rejected_total` | `role`, `phase`, `cause` |
| `federator_revocation_connections_terminated_total` | `role`, `cause` |
| `federator_ocsp_request_duration_seconds` | `role`, `outcome` |
| `federator_ocsp_errors_total` | `role`, `type` |
| `federator_revocation_cache_lookups_total` | `role`, `cache`, `result` (hit rate) |
| `cache_*{cache="federator.revocation.status"}` | in-memory cache statistics |
| `resilience4j_circuitbreaker_state{name="ocsp-responder"}` | circuit breaker state |

## Configuration reference

See the `Revocation` sections of `src/configs/server.properties`. Keys:

| Property | Default | Description |
|---|---|---|
| `revocation.enforcement.enabled` | `true` | Master switch |
| `revocation.enforcement.failClosed` | `true` | Reject when no valid status is available |
| `revocation.ocsp.path` | `/api/v1/certificate/ocsp` | Appended to `management.node.base.url` |
| `revocation.ocsp.requestTimeout` | `2` | Seconds per attempt |
| `revocation.ocsp.requireNonce` | `true` | Send and require a nonce |
| `revocation.ocsp.requireSignerEku` | `true` | Require `id-kp-OCSPSigning` on the signer (transitional `false`) |
| `revocation.ocsp.signerCommonName` | `ocsp-signer.management-node` | Signer CN accepted when the EKU is not required |
| `revocation.cache.type` | `memory` | `memory` or `redis` |
| `revocation.cache.ttl.seconds` | `300` | 1 to 600 |
| `revocation.cache.maxEntries` | `10000` | In-memory cache size |
| `revocation.ocsp.resilience.retry.maxAttempts` | `2` | Attempts in total |
| `revocation.ocsp.resilience.retry.initialWait` | `PT0.1S` | First retry wait |
| `revocation.ocsp.resilience.retry.maxBackoff` | `PT0.5S` | Retry wait cap |
| `revocation.ocsp.resilience.circuitBreaker.failureRateThreshold` | `50` | Percent |
| `revocation.ocsp.resilience.circuitBreaker.slidingWindowSize` | `10` | Calls |
| `revocation.ocsp.resilience.circuitBreaker.minimumNumberOfCalls` | `10` | Calls |
| `revocation.ocsp.resilience.circuitBreaker.waitDurationInOpenState` | `PT30S` | Open time |
| `server.maxConnectionAge.seconds` | `1800` with checks active | GOAWAY after this age |
| `server.maxConnectionAgeGrace.seconds` | not set | If set, calls still running this long after GOAWAY are ended |
| `server.maxConnectionIdle.seconds` | `60` with checks active | Close connections without calls after this idle time |
| `server.tlsSessionTimeout.seconds` | `300` | TLS session resumption limit |
| `metrics.enabled` / `metrics.port` | `true` / `9464` | Prometheus endpoint |
