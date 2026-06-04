# Java Buildpack Client Certificate Mapper

| Workflow | Status |
| -------- | ------ |
| CI | [![CI](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/ci.yml) |
| Release | [![Release](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/release.yml/badge.svg)](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/release.yml) |

The `java-buildpack-client-certificate-mapper` is a Servlet filter that maps the [`X-Forwarded-Client-Cert`][xfcc] header to the `javax.servlet.request.X509Certificate` (javax) or `jakarta.servlet.request.X509Certificate` (jakarta) Servlet attribute. Both raw PEM and [Envoy XFCC format][xfcc] are supported.

## Download

Pre-built jars are available on the [Releases page](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/releases):

- **Releases** — tagged versions (e.g. `v2.0.2`)
- **Snapshot** — latest build from `main` (pre-release, updated on every push)

## Development

The project requires Java 8. To build and test from source:

```shell
$ ./mvnw clean package
```

## XFCC Header Format

The filter supports both the raw PEM certificate format and the [Envoy XFCC format][xfcc]. In XFCC format, the header contains key-value fields such as `Hash=`, `Cert=`, and `Subject=`. Field names are matched case-insensitively. Multiple header values and the [RFC 9110][rfc9110] comma-delimited equivalent are both supported.

The `Hash=` field (a SHA-256 fingerprint of the leaf certificate, set by the router) is recognised for format detection and optionally sanity-checked, but it cannot be mapped to an `X509Certificate` without a `Cert=` field.

**Specifications:**
- [Envoy `x-forwarded-client-cert` header][xfcc] — XFCC field definitions (`By=`, `Hash=`, `Cert=`, `Subject=`, `URI=`, `DNS=`)
- [RFC 9110 §5.3][rfc9110] — HTTP header comma-delimited field values
- [Jakarta Servlet 6.0 specification][servlet-spec] — `jakarta.servlet.request.X509Certificate` attribute

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
