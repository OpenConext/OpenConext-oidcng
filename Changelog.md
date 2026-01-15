# Changelog

## 8.4.0
- Only call the `/attribute-manipulation` in the `/introspect` endpoint when the Resource Server has an institutionGUID ([#1050](https://github.com/OpenConext/OpenConext-myconext/issues/1050))
- Upgrade to Spring Boot 3.5.8
- Avoid `NullPointerException` in comparing redirect URI's with defensive comparisons
- Support for native applications with IPV6 [::1] as the hostname
- Upped dependencies for logstash, zxing, commons-io, jakarta.xml, actions/cache and codecov-action

## 8.3.0
- Only call the `/attribute-manipulation` in the `/introspect` endpoint when entityID's and institutionGUID's are different ([#1041](https://github.com/OpenConext/OpenConext-myconext/issues/1041))

## 8.2.0
- Added the authenticating authority to the user_info endpoint
- Upped dependencies for nimbusds, bouncycastle and opensaml 

## 8.1.1
- Bugfix for Spring Crypto not accepting BCrypt secrets longer than 72 bytes

## 8.1.0
- Allow POST requests to `/oidc/authorize` (enables form_post submissions) ([#263](https://github.com/OpenConext/OpenConext-oidcng/issues/263))
- Ensure URIs passed in the `login_hint` are absolute (PR [#271](https://github.com/OpenConext/OpenConext-oidcng/pull/271))
- Prevent duplicate keys ([#239](https://github.com/OpenConext/OpenConext-oidcng/issues/239))
- Do not expose mappings
- Add eduPersonAssurance claim
- Support preferred language user attribute
- Switch to JDK 21 and upgrade Spring Boot and dependencies (oauth2-oidc-sdk 11.23.1, OpenSAML 5.1.4, xmlsec 4.0.4, BouncyCastle 1.80, logstash-logback-encoder 8.1)
- Enable @Scheduled annotations in standalone mode
- Include SRAM services
- Build improvements: ARM images, Docker deployment refactoring, multi-module Maven structure
- CI and plugin upgrades

## 8.0.1
- Backward compatibility for comma-separated scope values ([#238](https://github.com/OpenConext/OpenConext-oidcng/issues/238))
- Device code flow textual fixes (NL)

## 8.0.0
- Migrate to Spring Boot 3 (incl. Spring Security 6) and align codebase accordingly
- Migrate SAML stack to OpenSAML 5; adapt request/response handling and validations
- Update OAuth 2.0 / OIDC SDK to 11.22.1 (PR [#229](https://github.com/OpenConext/OpenConext-oidcng/pull/229))
- Update GitHub Actions: setup-java to v4 (PR [#210](https://github.com/OpenConext/OpenConext-oidcng/pull/210)), codecov-action to 5.3.1 (PR [#227](https://github.com/OpenConext/OpenConext-oidcng/pull/227)), mongodb action to 1.12.0 (PR [#222](https://github.com/OpenConext/OpenConext-oidcng/pull/222))
- Ensure the original SAML AuthnRequest ID is preserved in the authentication flow
- Upgrade mail SMTP dependency and related test adjustments
- update PKCE-related test vectors to compliant values
