# Changelog

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
