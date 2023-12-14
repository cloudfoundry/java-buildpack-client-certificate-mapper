#!/usr/bin/env bash

set -euo pipefail

[[ -d $PWD/maven && ! -d $HOME/.m2 ]] && ln -s $PWD/maven $HOME/.m2

export REPOSITORY="${PWD}"/repository

cd java-buildpack-client-certificate-mapper
./mvnw -Dmaven.test.skip=true deploy -DcreateChecksum=true -DaltDeploymentRepository="local::default::file://${REPOSITORY}"

