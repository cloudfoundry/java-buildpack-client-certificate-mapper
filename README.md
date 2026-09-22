# Java Buildpack Client Certificate Mapper

| Workflow | Status |
| -------- | ------ |
| CI | [![CI](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/ci.yml) |
| Release | [![Release](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/release.yml/badge.svg)](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/release.yml) |

A Servlet filter that maps the [`X-Forwarded-Client-Cert`][xfcc] (XFCC) header set by a fronting proxy to the standard `javax.servlet.request.X509Certificate` / `jakarta.servlet.request.X509Certificate` request attribute, so your app reads the client certificate as it would behind direct mTLS.

- Accepts base64-encoded DER and URL-encoded PEM certificates (nginx, CF Gorouter `xfcc_format: raw`) and the structured [Envoy XFCC field format][xfcc] -- `Hash=`, `Cert=`, `Subject=` (Envoy, CF Gorouter `xfcc_format: envoy`).
- Also exposes the Cloud Foundry app/space/org identity parsed from the Subject DN, so apps behind an mTLS domain can identify the caller when no full certificate is forwarded.
- Your application code depends on no class from this library.

> **Trust boundary:** this filter maps the header verbatim. It does **not** verify certificate trust, validity, or proof of possession -- those come from the proxy that terminated the mTLS connection. The mapped attributes are trustworthy only if requests reach your app exclusively via that proxy. See [docs/TRUST-BOUNDARY.md](docs/TRUST-BOUNDARY.md).

## Getting started

On Cloud Foundry with the Java buildpack, the jar is added to your application automatically.

Otherwise take a jar from the [Releases page](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/releases) -- tagged releases such as `v2.1.0`, or **Snapshot** for the latest `main` build. Maven Central has not been published to since `2.0.1`.

The filter registers itself -- no `web.xml` entry or `@Bean`:

- **Servlet containers (javax and jakarta):** via `ServletContainerInitializer`, mapped to `/*` for all dispatcher types.
- **Spring Boot:** via auto-configuration, at `Ordered.HIGHEST_PRECEDENCE`, active only on Cloud Foundry (`@ConditionalOnCloudPlatform(CLOUD_FOUNDRY)`).

## Settings

All options are JVM system properties.

| Property | Default | What it does |
| --- | --- | --- |
| `org.cloudfoundry.router.certificate.cache.enabled` | `false` | Cache parsed certificates and reuse them across requests. Opt-in while it gathers field experience. |
| `org.cloudfoundry.router.certificate.cache.size` | `128` | Entries per cache generation; about `2 x size` cached XFCC entries (concurrent misses can briefly add one per thread) (~0.4-2.6 MB for CF-sized headers at the default). |
| `org.cloudfoundry.router.certificate.header.hide` | `false` | Hide the XFCC header from downstream filters and servlets after parsing. |
| `org.cloudfoundry.router.certificate.provider` | platform default | JCA provider used to parse certificates, e.g. `BC`. Useful only if the application already registers it -- see [docs/PROVIDERS.md](docs/PROVIDERS.md). |

[Configuration](#configuration) covers when to change these; [docs/PERFORMANCE.md](docs/PERFORMANCE.md) has the measurements.

The filter logs its effective configuration once at startup, at `INFO`:

```
Mapping X-Forwarded-Client-Cert to the jakarta.servlet.request.X509Certificate request attribute; certificate cache enabled (org.cloudfoundry.router.certificate.cache.size=128 entries per generation, about 256 cached XFCC entries); X-Forwarded-Client-Cert header stripping disabled (org.cloudfoundry.router.certificate.header.hide=true to enable); certificates parsed with JCA provider BC
```

The provider named is the one actually in use -- after any fallback, and including one the application registered first -- so it can differ from what `org.cloudfoundry.router.certificate.provider` asked for.

## Usage

### Read the client certificate

Use the `jakarta.` attribute name on Jakarta Servlet containers (Tomcat 10+, Spring Boot 3+), the `javax.` name on older ones:

```java
X509Certificate[] chain =
    (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
if (chain != null && chain.length > 0) {
    X509Certificate clientCert = chain[0]; // leaf certificate
    clientCert.checkValidity();            // optional: the filter does not enforce validity
}
```

Spring MVC controllers can inject it with `@RequestAttribute`:

```java
@GetMapping("/whoami")
String whoami(@RequestAttribute("jakarta.servlet.request.X509Certificate")
              X509Certificate[] chain) {
    return chain[0].getSubjectX500Principal().getName();
}
```

### Read CF identity without the full certificate

When the router forwards only `Hash=` and `Subject=` -- as CF Gorouter does on an mTLS domain with `xfcc_format: envoy` -- no `X509Certificate` is available, but the CF identity is still parsed from the Subject DN:

```java
String appGuid   = (String) request.getAttribute("org.cloudfoundry.router.xfcc.app.guid");
String spaceGuid = (String) request.getAttribute("org.cloudfoundry.router.xfcc.space.guid");
String orgGuid   = (String) request.getAttribute("org.cloudfoundry.router.xfcc.org.guid");
```

### Request attributes

Set when the header is in XFCC format (for multi-entry headers, the first entry containing the field wins). Any attribute may be `null` -- the header may be absent or carry only some fields.

| Attribute | Source | Value |
|-----------|--------|-------|
| `org.cloudfoundry.router.xfcc.hash` | `Hash=` | SHA-256 fingerprint of the client certificate |
| `org.cloudfoundry.router.xfcc.subject` | `Subject=` | Full Subject DN of the client certificate |
| `org.cloudfoundry.router.xfcc.app.guid` | `Subject=` `OU=app:<guid>` | CF app GUID |
| `org.cloudfoundry.router.xfcc.space.guid` | `Subject=` `OU=space:<guid>` | CF space GUID |
| `org.cloudfoundry.router.xfcc.org.guid` | `Subject=` `OU=organization:<guid>` | CF organization GUID |
| `org.cloudfoundry.router.xfcc.instance.guid` | `Subject=` `CN=<guid>` | CF app instance GUID |

Format detection, fallback behaviour and Gorouter `xfcc_format` specifics are in [docs/XFCC.md](docs/XFCC.md).

## Configuration

### Certificate caching

Off by default. Set `org.cloudfoundry.router.certificate.cache.enabled=true` to switch it on.

Parsed results are then reused across requests carrying the same header value, skipping the base64/PEM decode, the ASN.1 parse and the Subject DN parse. Per call: 24.3 us to 3.0 us for an Envoy `Cert=` header, 5.2 us to 2.3 us for a Gorouter raw base64 certificate, 2.1 us to 0.5 us for a CF app-identity header. Entries are keyed by the header value, so only a byte-for-byte identical header hits.

`cache.size` is the entries per generation, two generations, so `2 x size` entries -- plus up to one per thread missing at the same moment, since a generation is only checked for room before an insert -- roughly 0.4-2.6 MB at the default of 128 for CF-sized headers, more for chains. Size it to the number of distinct client certificates you serve, or leave it off: a cache that mostly misses is overhead.

**Seeing whether it pays.** Hit rate is the number that matters, readable two ways:

- **On generation rotation**, a statistics snapshot -- hits, misses, hit rate, rotations, capacity -- first at `INFO` and later at `FINE`. Rotation needs a generation's worth of misses, so a working set that fits the cache may never log it.
- **Per lookup** at `FINE`, one line per hit or miss. Too chatty to leave on, useful for a short sample.

A low hit rate means the working set exceeds `2 x cache.size`: raise it or turn the cache off. It is opt-in deliberately -- the measurements are a benchmark, not production traffic. Note the JVM already caches parsed certificates (`sun.security.provider.X509Factory.certCache`, 750 soft-referenced entries), so applications serving fewer distinct callers than that are partly cached already; this cache earns most beyond that point, and on the XFCC field and Subject DN parsing the JDK's does not cover. [docs/PERFORMANCE.md](docs/PERFORMANCE.md) has the full picture.

Cached certificates are **not** expiry-checked on retrieval; see [docs/TRUST-BOUNDARY.md](docs/TRUST-BOUNDARY.md).

### Certificate provider

The platform provider (`SUN`) keeps its own 750-entry certificate cache but takes a lock on every lookup, so concurrent parsing scales poorly: at four threads ~46% of thread time is blocked and four cores return 1.4x the throughput of one, not 4x. JDK 27 narrows that lock ([JDK-8345954](https://bugs.openjdk.org/browse/JDK-8345954)) -- the parse moves outside it, which helps cache misses -- but lookups still serialize, and measured blocked time is the same on JDK 25 and 27.

`org.cloudfoundry.router.certificate.provider=BC` parses through BouncyCastle, which has no such lock. Worth doing only with more distinct client certificates than the JVM cache holds *and* real concurrency. The filter never registers a provider itself, and an unusable name degrades to the platform default with a warning rather than failing startup.

Provider order can select a provider implicitly too -- including the trap where `Security.addProvider(new BouncyCastleProvider())` leaves parsing on `SUN`. That, the measurements for `BC` and the platform default, and when switching is worth it, are in [docs/PROVIDERS.md](docs/PROVIDERS.md).

### Header hiding

With `org.cloudfoundry.router.certificate.header.hide=true`, the header is hidden from downstream filters and servlets once parsed, via an `HttpServletRequestWrapper`. That keeps large base64 values out of request logging filters (`CommonsRequestLoggingFilter`, Tomcat `RequestDumperValve`), security filters that iterate all headers, and Servlet-`Filter`-based tracing placed after this filter.

Opt-in, because it changes downstream *behaviour*: code that gates logic on the raw header's presence would silently stop seeing it -- a fail-open risk. Enable it once nothing downstream depends on the raw header.

Caveats:

- Affects only code reading the header via the wrapped `HttpServletRequest` *after* this filter. Bytecode-instrumented tracing agents (e.g. the OpenTelemetry Java agent) capture headers at the container / dispatch level, before the wrapper applies.
- The header is hidden whenever present, even when parsing failed -- downstream code must not read "no header" as "no client certificate was presented".
- **Async:** the wrapper preserves itself across `startAsync()`, but if a downstream filter wraps the response again before calling the no-arg `startAsync()`, that newer response wrapper is not visible here and a stale response is passed to `startAsync(request, response)` -- a known limitation.

## Error handling

A malformed header never fails the request: the filter logs a `WARNING` and passes the request on with **no** certificate and **no** XFCC attributes. One bad entry in a multi-entry header drops them all. Details in [docs/ERROR-HANDLING.md](docs/ERROR-HANDLING.md).

## Debug logging

The filter uses Java Util Logging. Set the `org.cloudfoundry.router` logger to `FINE` to log the recognised XFCC field names present in each header (e.g. `Hash`, `Cert`, `Subject`). Certificate values are never logged.

## More documentation

- [docs/TRUST-BOUNDARY.md](docs/TRUST-BOUNDARY.md) -- what the filter does and does not guarantee, and what your app should check
- [docs/XFCC.md](docs/XFCC.md) -- header formats, detection rules, CF Gorouter specifics
- [docs/ERROR-HANDLING.md](docs/ERROR-HANDLING.md) -- what happens when the header is malformed, and what fails the request
- [docs/PROVIDERS.md](docs/PROVIDERS.md) -- choosing the JCA provider that parses certificates
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md) -- cache design, benchmarks, memory
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) -- building from source, CI workflows
- [docs/RELEASE.md](docs/RELEASE.md) -- making a release, and how a release reaches the Java buildpack

## License

This project is released under version 2.0 of the [Apache License][l].

[l]: https://www.apache.org/licenses/LICENSE-2.0
[xfcc]: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
