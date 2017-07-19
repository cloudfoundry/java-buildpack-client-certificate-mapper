# Java Buildpack Client Certificate Mapper

| Job | Status
| --- | ------
| `unit-test-7` | [![unit-test-master](https://java-experience.ci.springapps.io/api/v1/teams/java-experience/pipelines/java-buildpack-client-certificate-mapper/jobs/unit-test-7/badge)](https://java-experience.ci.springapps.io/teams/java-experience/pipelines/java-buildpack-client-certificate-mapper/jobs/unit-test-7)
| `unit-test-8` | [![unit-test-master](https://java-experience.ci.springapps.io/api/v1/teams/java-experience/pipelines/java-buildpack-client-certificate-mapper/jobs/unit-test-8/badge)](https://java-experience.ci.springapps.io/teams/java-experience/pipelines/java-buildpack-client-certificate-mapper/jobs/unit-test-8)
| `deploy` | [![deploy-master](https://java-experience.ci.springapps.io/api/v1/teams/java-experience/pipelines/java-buildpack-client-certificate-mapper/jobs/deploy/badge)](https://java-experience.ci.springapps.io/teams/java-experience/pipelines/java-buildpack-client-certificate-mapper/jobs/deploy)

The `java-buildpack-client-certificate-mapper` is a Servlet filter that maps the `X-Forwarded-Client-Cert` to the `javax.servlet.request.X509Certificate` Servlet attribute.

## Development
The project depends on Java 7.  To build from source, run the following:

```shell
$ ./mvnw clean package
```

## Contributing
[Pull requests][u] and [Issues][e] are welcome.

## License
This project is released under version 2.0 of the [Apache License][l].

[e]: https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/issues
[l]: https://www.apache.org/licenses/LICENSE-2.0
[u]: https://help.github.com/articles/using-pull-requests
