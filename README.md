# Java Buildpack Client Certificate Mapper

| Workflow | Status |
| -------- | ------ |
| CI | [![CI](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/ci.yml) |
| Release | [![Release](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/release.yml/badge.svg)](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/release.yml) |

The `java-buildpack-client-certificate-mapper` is a Servlet filter that maps the [`X-Forwarded-Client-Cert`][xfcc] header to the `javax.servlet.request.X509Certificate` (javax) or `jakarta.servlet.request.X509Certificate` (jakarta) Servlet attribute. Both base64-encoded DER and URL-encoded PEM certificates, as well as [Envoy XFCC format][xfcc], are supported.

It supports both the structured XFCC field format (as produced by Envoy, and by CF Gorouter with `xfcc_format: envoy`) and raw Base64/URL-encoded certificate headers (as produced by nginx, and by CF Gorouter with `xfcc_format: raw`).

## Download

Pre-built jars are available on the [Releases page](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/releases):

- **Releases** — tagged versions (e.g. `v2.0.2`)
- **Snapshot** — latest build from `main` (pre-release, updated on every push)

## Usage

Once the filter is mapped in your app, read the client certificate and the Cloud Foundry identity from the standard Servlet request attributes. Your application code does not need to depend on any class from this library.

### Read the client certificate

The parsed certificate chain is stored under the standard Servlet attribute. Use the `jakarta.` name on Jakarta Servlet containers (Tomcat 10+, Spring Boot 3+) or the `javax.` name on older containers:

```java
X509Certificate[] chain =
    (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
if (chain != null && chain.length > 0) {
    X509Certificate clientCert = chain[0]; // leaf certificate
    clientCert.checkValidity();            // optional: the filter does not enforce validity
}
```

Spring MVC controllers can inject it directly with `@RequestAttribute`:

```java
@GetMapping("/whoami")
String whoami(@RequestAttribute("jakarta.servlet.request.X509Certificate")
              X509Certificate[] chain) {
    return chain[0].getSubjectX500Principal().getName();
}
```

### Read CF identity without the full certificate

When the router forwards only `Hash=` and `Subject=` — as CF Gorouter does on an mTLS domain configured with `xfcc_format: envoy` — no `X509Certificate` is available, but the filter still parses the CF app identity from the Subject DN into request attributes:

```java
String appGuid   = (String) request.getAttribute("org.cloudfoundry.router.xfcc.app.guid");
String spaceGuid = (String) request.getAttribute("org.cloudfoundry.router.xfcc.space.guid");
String orgGuid   = (String) request.getAttribute("org.cloudfoundry.router.xfcc.org.guid");
```

See [Request attributes set from XFCC fields](#request-attributes-set-from-xfcc-fields) for the full list. Any attribute may be `null` — always null-check, since the header may be absent or carry only some fields.

### Trust boundary and certificate validity

This filter maps the incoming `X-Forwarded-Client-Cert` header **verbatim**. It does **not** verify certificate trust, validity, or that the caller proved possession of the private key. Those guarantees come entirely from whichever fronting proxy terminated the (mutual) TLS connection and set the header — CF Gorouter is one example, but the same applies to any router or gateway, inside or outside CF.

The mapped attributes are therefore trustworthy **only** if requests reach your app exclusively via that trusted proxy, and any client-supplied copy of the header on untrusted inbound paths is stripped by it. Whether the proxy strips and replaces the header is a proxy configuration choice (e.g. CF Gorouter `forwarded_client_cert: sanitize_set`, or Envoy's default `SANITIZE`/`SANITIZE_SET`); pass-through modes (Gorouter `always_forward`, Envoy `ALWAYS_FORWARD_ONLY`) forward whatever the client sent. If your instance is reachable directly, bypassing the proxy, the header is attacker-controllable and no app-side check can recover the missing possession proof — a forwarded certificate proves only that the proxy *saw* it, not that the caller *holds* it.

There are two distinct cases for what your app can check:

- **Identity-only header (`Hash=` + `Subject=`, e.g. CF app-identity on an mTLS domain).** No `X509Certificate` is mapped, so your app **cannot** call `checkValidity()` — there are no certificate bytes. It does not need to: the proxy already required and validated the client certificate during the mTLS handshake (chain and validity period) before emitting the header, and CF instance-identity certificates are short-lived. Treat the `xfcc.*` attributes as a post-validation identity assertion, trusted transitively via the proxy.
- **Full-certificate header (`Cert=`, or a raw certificate value).** An `X509Certificate` is mapped, so your app **can and should** enforce its own checks where appropriate — e.g. `cert.checkValidity()` and verifying the chain against a trusted CA — as defence in depth. This filter does none of that.

## XFCC Header Format

The filter supports base64-encoded DER certificates, URL-encoded PEM certificates, and the [Envoy XFCC format][xfcc]. In XFCC format, the header contains key-value fields such as `Hash=`, `Cert=`, and `Subject=`. Field names are matched case-insensitively. Multiple header values and the [RFC 9110][rfc9110] comma-delimited equivalent are both supported.

The `Hash=` field (a SHA-256 fingerprint of the leaf certificate, set by the router) is recognised for format detection and optionally sanity-checked, but it cannot be mapped to an `X509Certificate` without a `Cert=` field.

### XFCC detection and fallback behaviour

An entry is detected as XFCC format when it structurally begins with a short (≤ 20 characters) all-letter key followed by `=`, **and** contains at least one of `Hash=`, `Cert=`, or `Chain=`. JSON format is not supported.

If an entry passes the structural check but contains none of the recognised cert-related fields (e.g. only unknown future fields), it is treated as a raw certificate value; parsing will fail and a warning is logged. This preserves the same external behaviour as the raw-cert fallback path.

### CF Gorouter XFCC fields

CF Gorouter's XFCC output depends on the per-domain `xfcc_format` setting:

- **`xfcc_format: envoy`** (used on mTLS domains such as CF app-identity) emits the compact field form `Hash=<sha256-hex>;Subject="<DN>"` — **only** `Hash=` and `Subject=`. Gorouter never emits a `Cert=` field in this mode.
- **`xfcc_format: raw`** (the non-mTLS default) emits the **whole leaf certificate** as the base64 header value, with no `Hash=`/`Subject=`/`Cert=` field prefix.

So the `Cert=` field this library parses comes from a real Envoy proxy (or another XFCC producer), not from Gorouter — Gorouter conveys the full certificate via the raw format instead. `By=`, `URI=`, and `DNS=` are not emitted for CF app-identity certs (they carry no URI/DNS SANs) and are not recognised by this library.

### Request attributes set from XFCC fields

When the header is in XFCC format, the filter sets the following request attributes (first entry that contains the field wins for multi-entry headers):

| Attribute | Source | Value |
|-----------|--------|-------|
| `org.cloudfoundry.router.xfcc.hash` | `Hash=` | SHA-256 fingerprint of the client certificate |
| `org.cloudfoundry.router.xfcc.subject` | `Subject=` | Full Subject DN of the client certificate |
| `org.cloudfoundry.router.xfcc.app.guid` | `Subject=` `OU=app:<guid>` | CF app GUID parsed from the Subject DN |
| `org.cloudfoundry.router.xfcc.space.guid` | `Subject=` `OU=space:<guid>` | CF space GUID parsed from the Subject DN |
| `org.cloudfoundry.router.xfcc.org.guid` | `Subject=` `OU=organization:<guid>` | CF organization GUID parsed from the Subject DN |
| `org.cloudfoundry.router.xfcc.instance.guid` | `Subject=` `CN=<guid>` | CF app instance GUID parsed from the Subject DN |

The CF Subject DN format is: `CN=<instance-guid>,OU=app:<app-guid>,OU=space:<space-guid>,OU=organization:<org-guid>`.

These attributes are set regardless of whether a `Cert=` field is present, so applications can identify the caller even when only a `Hash=` and `Subject=` are forwarded by the router.

Unknown fields are silently skipped and logged at `FINE` level.

**Specifications:**
- [Envoy `x-forwarded-client-cert` header][xfcc] — XFCC field definitions (`Hash=`, `Cert=`, `Chain=`, `Subject=`)
- [RFC 9110 §5.3][rfc9110] — HTTP header comma-delimited field values
- [Jakarta Servlet 6.0 specification][servlet-spec] — `jakarta.servlet.request.X509Certificate` attribute

## Configuration

All options are controlled via JVM system properties.

### `org.cloudfoundry.router.certificate.cache.enabled`

Enables or disables certificate caching. When enabled, parsed `X509Certificate` objects are cached and reused across requests for the same certificate, avoiding repeated DER/PEM parsing.

| Value | Behaviour |
|-------|-----------|
| `true` _(default)_ | Caching enabled |
| `false` | Caching disabled; every request parses the certificate from scratch |

Caching is **on by default**. Set to `false` if you'd rather have every request parse the certificate from scratch — e.g. while profiling, or if the ~1.5 MB worst-case memory (see below) is a concern for your deployment.

**Only full-certificate headers are cached.** The cache exists to amortise the expensive ASN.1 parse of an actual certificate, so it is engaged only when the header carries a certificate to decode: an XFCC `Cert=` field, or a raw (non-XFCC) certificate value. Identity-only XFCC headers that carry just `Hash=`/`Subject=` (e.g. the CF app-identity headers on an mTLS domain) map no `X509Certificate` and are parsed inline regardless of this setting — caching them would only add a per-request SHA-256 keying cost for no benefit. See [Trust boundary and certificate validity](#trust-boundary-and-certificate-validity).

**Multiple headers vs. a certificate chain.** A request can carry multiple `X-Forwarded-Client-Cert` entries — as separate header lines or comma-joined in one line (see [XFCC Header Format](#xfcc-header-format) above) — typically from multiple hops each terminating their own mTLS connection and appending their own entry. Each entry is a **separate leaf certificate**, cached **independently** under its own SHA-256 key; a cache hit or miss on one entry never affects another, and the mapped `X509Certificate[]` attribute preserves header order regardless of cache state. This is unrelated to a single certificate's **trust chain** (the XFCC `Chain=` field, carrying intermediate CA certificates for one leaf cert) — that field is not supported at all: an entry with `Chain=` but no `Cert=` maps no certificate and is never cached.

**Cache key:** The cache key is a 64-character SHA-256 hex digest of the header entry as received — not the raw string itself, and not the router-supplied `Hash=` field, which external clients could inject when header stripping is disabled. Using the raw string as key would mean every lookup pays the full cost of hashing and comparing the ~1.3 KB value: `String` caches its computed hash in a private field after the first call, but each request produces a fresh `String` from XFCC substring parsing — a new object that has never computed that hash before — so the per-object cache never carries over between requests even though the hash value itself is identical for identical content; a full-length `equals()` is also needed on every lookup since the objects are never the same reference. Only a request carrying the actual certificate can produce a cache hit. The digest is taken over the header string as received (URL-encoded PEM or base64 DER), not over the decoded DER bytes, so it intentionally differs from the Envoy XFCC `Hash=` field (SHA-256 of the DER) and the two are not cross-comparable.

**Why a short derived key rather than the raw certificate string.** Using the full ~1.3 KB `Cert=` value directly as the map key was measured to burn most of the cache's benefit: a hit still needs a full-length `String.equals()`, and hashing the whole key on every lookup. JMH on JDK 25 (single-threaded, average time, 5+5 iterations × 2 forks) using a typical ~1.3 KB CF app-identity certificate:

| Strategy | ns/op | vs. no cache |
| --- | --- | --- |
| Parse the cert every call (no cache) | ~3620 | 1× (baseline) |
| Cache hit keyed by raw ~1.3 KB cert string | ~1890 | 1.9× faster |
| Cache hit keyed by 64-char SHA-256 hex digest | **~130** | **28× faster** |

The short digest recovers ~14.6× of the per-hit cost. Under real concurrent load this compounded per-request CPU is what previously made a raw-key cache measurably worse than no cache at all.

**Memory:** The cache uses a generational eviction strategy (two generations of up to 128 entries each, configurable via `org.cloudfoundry.router.certificate.cache.size`). The cache **keys** are cheap: 64-character SHA-256 hex digests, ~16 KB total across 256 entries. The memory actually comes from the cached **values** — each is a `ParsedXfcc` bundle holding the parsed `X509Certificate` plus the `XfccEntry` it was derived from, which retains the raw `Cert=` substring (typically 1–2 KB). With both generations full (~256 entries), that's a worst-case total of roughly **~1.5 MB**. Disable caching if this is a concern.

**Security note:** Cached entries are not expiry-checked on retrieval. The filter does not validate certificate validity on cache hits (nor on misses) — consistent with behaviour before caching was introduced. Applications that require expiry enforcement should check `X509Certificate.checkValidity()` on the mapped request attribute.

**Security note — hash collisions:** Cache correctness depends on the SHA-256 key uniquely identifying the header value it was derived from. A collision (two different header values digesting to the same key) would make the cache return the wrong parsed `X509Certificate` for a request — an integrity issue, not just a performance one. This is considered cryptographically infeasible: SHA-256 offers ~2^128 collision resistance, far beyond what any attacker can feasibly search for, and the input space per generation (≤ 128 live entries at a time, refreshed as certs rotate) gives no practical advantage to a birthday-style attack either. No known SHA-256 collision exists as of this writing.

### `org.cloudfoundry.router.certificate.cache.size`

Controls the number of entries per cache generation. The total number of cached certificates at any time is at most `2 × size`.

| Value | Behaviour |
|-------|-----------|
| `128` _(default)_ | ~256 entries max, ~1.5 MB worst-case memory |
| any positive integer | Custom generation size; higher values trade more memory for fewer evictions |

Invalid or non-positive values are ignored and the default is used (a warning is logged).

### `org.cloudfoundry.router.certificate.header.hide`

When enabled, the `X-Forwarded-Client-Cert` header is hidden from all downstream filters and servlets after the certificate has been parsed and stored as a request attribute. This prevents large uuencoded PEM/DER certificate values from being needlessly processed by downstream infrastructure such as:

- Request logging filters (`CommonsRequestLoggingFilter`, Tomcat `RequestDumperValve`)
- Security filters that iterate all headers
- Servlet-`Filter`-based tracing instrumentation (e.g. Micrometer Tracing / Spring Cloud Sleuth's Brave filter) placed after this filter in the chain

> **Note:** This only affects code that reads the header via the (wrapped) `HttpServletRequest` *after* this filter runs. Bytecode-instrumented tracing agents (e.g. the OpenTelemetry Java agent) commonly capture headers at the servlet container / dispatch level, before this filter's wrapper takes effect — for those, hiding the header has no impact, and filter ordering doesn't help either.

The wrapper is only created when the header is actually present on the request, so there is no overhead for requests without a client certificate.

| Value | Behaviour |
|-------|-----------|
| `false` _(default)_ | Header passed through unchanged |
| `true` | Header hidden from downstream filters via `HttpServletRequestWrapper` |

Header hiding is **opt-in** (disabled by default), unlike certificate caching — this setting can change downstream *behaviour*, not just performance: any code after this filter in the chain that gates logic on the presence of the raw header would silently stop seeing it. That's a fail-open risk — a downstream security check that only activates "when this header is present" would quietly stop firing, with no error or log to signal it — so this filter cannot safely enable it by default without knowing what every consumer's downstream chain does. Enable it explicitly once you've confirmed no downstream code depends on the raw header being present.

> **Note:** Hiding the header does not free the underlying string memory during the request — it prevents downstream code from reading it. Memory is reclaimed when the request completes and the original request object is GC'd.

**Benchmark:** Measured with a Spring Boot app behind `CommonsRequestLoggingFilter` (which reads and logs all request headers, including the raw XFCC header, on every request), with the raw XFCC header as forwarded by CF Gorouter. `byte[]` allocation captured via Java Flight Recorder over a 40-second run at 500 requests/second:

| `header.hide` | `cache.enabled` | Request logging filter | `byte[]` allocation |
|---|---|---|---|
| `false` | `false` | enabled | 1.47 GiB |
| `true` | `false` | enabled | 791 MB |
| `true` | `true` | enabled | 547 MB |
| `true` | `true` | disabled | 60.5 MB |

The largest impact by far is the `byte[]` allocations inside the logging filter itself — hiding the header is what removes most of them; caching removes the remaining repeated certificate parsing on top of that.

## Development

The project requires Java 8. To build and test from source:

```shell
$ ./mvnw clean package
```

## Error Handling

Certificate parse failures (invalid Base64, invalid `CertificateFactory` input) are caught inside `doFilter()`, logged as a `WARNING`, and the request is passed to the next filter without setting the certificate attribute. This behaviour is unchanged from earlier versions.

**Behaviour change (this version):** previously, a malformed URL-encoded value in the header (e.g. a `%GG` sequence that `URLDecoder` cannot decode) caused an `IllegalArgumentException` to propagate uncaught out of `doFilter()`, typically resulting in a 500 response. From this version that exception is caught alongside `CertificateException` and the same log-and-continue behaviour applies.

## Debug Logging

The filter uses Java Util Logging (JUL). To enable debug output, set the logger level for `org.cloudfoundry.router` to `FINE`. When enabled, the filter logs the XFCC field names present in each header (e.g. `Hash`, `Cert`, `Subject`). Certificate values are never logged.

## CI / Workflows

| Workflow | Trigger | Description |
| -------- | ------- | ----------- |
| **CI** | push to `main`, pull requests, manual | Builds and runs all tests. On push to `main` (after tests pass) also publishes the jar to the rolling snapshot release. |
| **Release** | manual (`workflow_dispatch`) | Bumps to release version, tags `vX.Y.Z`, creates a GitHub Release with the jar attached, then advances to the next SNAPSHOT version. |

All workflows can be triggered manually from **Actions → select workflow → Run workflow** in the GitHub UI.

## License
This project is released under version 2.0 of the [Apache License][l].

[l]: https://www.apache.org/licenses/LICENSE-2.0
[xfcc]: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
[rfc9110]: https://www.rfc-editor.org/rfc/rfc9110#section-5.3
[servlet-spec]: https://jakarta.ee/specifications/servlet/6.0/
