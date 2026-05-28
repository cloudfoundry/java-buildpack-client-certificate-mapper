# Java Buildpack Client Certificate Mapper

| Workflow | Status |
| -------- | ------ |
| CI | [![CI](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/ci.yml) |
| Release | [![Release](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/release.yml/badge.svg)](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/release.yml) |

The `java-buildpack-client-certificate-mapper` is a Servlet filter that maps the `X-Forwarded-Client-Cert` header to the `javax.servlet.request.X509Certificate` (javax) or `jakarta.servlet.request.X509Certificate` (jakarta) Servlet attribute.

## Download

Pre-built jars are available on the [Releases page](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/releases):

- **Releases** — tagged versions (e.g. `v2.0.2`)
- **Snapshot** — latest build from `main` (pre-release, updated on every push)

## Development

The project requires Java 8. To build and test from source:

```shell
$ ./mvnw clean package
```

## CI / Workflows

| Workflow | Trigger | Description |
| -------- | ------- | ----------- |
| **CI** | push to `main`, pull requests, manual | Builds and runs all tests. On push to `main` (after tests pass) also publishes the jar to the rolling snapshot release. |
| **Release** | manual (`workflow_dispatch`) | Bumps to release version, tags `vX.Y.Z`, creates a GitHub Release with the jar attached, then advances to the next SNAPSHOT version. |

All workflows can be triggered manually from **Actions → select workflow → Run workflow** in the GitHub UI.

## Contributing
[Pull requests][u] and [Issues][e] are welcome.

## License
This project is released under version 2.0 of the [Apache License][l].

[e]: https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/issues
[l]: https://www.apache.org/licenses/LICENSE-2.0
[u]: https://help.github.com/articles/using-pull-requests
