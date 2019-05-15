# OpenConext-oidcng
[![Build Status](https://travis-ci.org/OpenConext/OpenConext-oidcng.svg)](https://travis-ci.org/OpenConext/OpenConext-oidcng)
[![codecov.io](https://codecov.io/github/OpenConext/OpenConext-oidcng/coverage.svg)](https://codecov.io/github/OpenConext/OpenConext-oidcng)

OpenID Connect - SAML proxy

## [Getting started](#getting-started)

### [System Requirements](#system-requirements)

- Java 8
- Maven 3.x
- MongoDB 3.4.x
- ansible 2.x.x

## [Building and running](#building-and-running)

`mvn clean install`

### [The oidcng-server](#oidcng-server)

This project uses Spring Boot and Maven. To run locally, type:

`mvn spring-boot:run -Drun.jvmArguments="-Dspring.profiles.active=dev"`

When developing, it's convenient to just execute the applications main-method. The `dev` profile uses a fake authorization
to bypass the redirect to EB.

### [Endpoints](#endpoint)

TODO
```
https://oidcng.test2.surfconext.nl/oidc/.well-known/openid-configuration
https://oidcng.test2.surfconext.nl/oidc/generate-jwks-keystore
https://oidcng.test2.surfconext.nl/oidc/generate-secret-key-set
https://oidcng.test2.surfconext.nl/oidc/certs 
```

### [Testing](#testing)

Ensure there is a valid RP in the OpenConext proxy defined in the key `spring.security.saml2.service-provider.providers[0].metadata`
of the `application.yml` and then go to
the [authorization endpoint](http://localhost:8080/oidc/authorize?response_type=code&client_id=http@//mock-sp&scope=openid&redirect_uri=http://localhost:8080)

