# Development

The build targets Java 8 bytecode (`maven.compiler` source/target 8); CI builds and tests on Temurin JDK 21.

```shell
$ ./mvnw clean package
```

## CI / Workflows

| Workflow | Trigger | Description |
| -------- | ------- | ----------- |
| **CI** | push to `main`, pull requests, manual | Builds and runs all tests. On push to `main` (after tests pass) also publishes the jar to the rolling snapshot release. |
| **Release** | publishing a GitHub release with a `vX.Y.Z` tag; manual re-run with a tag | Builds and tests the tag as version `X.Y.Z`, checks every artifact carries that version, and attaches the jars to the release. See [RELEASE.md](RELEASE.md). |

All workflows can be triggered from **Actions -> select workflow -> Run workflow**.

The project version is `${revision}`, a property in the root `pom.xml`; see [RELEASE.md](RELEASE.md).
