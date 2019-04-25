# OpenConext-oidc-ng
[![Build Status](https://travis-ci.org/oharsta/oidc-ng.svg)](https://travis-ci.org/oharsta/oidc-ng)
[![codecov.io](https://codecov.io/github/oharsta/oidc-ng/coverage.svg)](https://codecov.io/github/oharsta/oidc-ng)

OpenID Connect - SAML proxy

## [Getting started](#getting-started)

### [System Requirements](#system-requirements)

- Java 8
- Maven 3.x
- MongoDB 3.4.x
- ansible 2.7.X

## [Building and running](#building-and-running)

### [The manage-server](#manage-server)

This project uses Spring Boot and Maven. To run locally, type:

`mvn spring-boot:run -Drun.jvmArguments="-Dspring.profiles.active=dev"`

When developing, it's convenient to just execute the applications main-method. Don't forget to set the active 
profile to dev.

### [Wiki](#wiki)

See the oidc-ng [github wiki](https://github.com/oharsta/oidc-ng/wiki) for additional documentation.

### [Testing](#testing)

Go to the [authorization endpoint](http://localhost:8080/oidc/authorize?response_type=code&client_id=http@//mock-sp&scope=openid&redirect_uri=http://localhost:8080)

