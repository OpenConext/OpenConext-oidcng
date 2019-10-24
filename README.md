# OpenConext-oidcng
[![Build Status](https://travis-ci.org/OpenConext/OpenConext-oidcng.svg)](https://travis-ci.org/OpenConext/OpenConext-oidcng)
[![codecov.io](https://codecov.io/github/OpenConext/OpenConext-oidcng/coverage.svg)](https://codecov.io/github/OpenConext/OpenConext-oidcng)

OpenID Connect - SAML proxy

## [Getting started](#getting-started)

### [System Requirements](#system-requirements)

- Java 8
- Maven 3.x
- MongoDB 3.4.x

## [Building and running](#building-and-running)

`mvn clean install`

### [The oidcng-server](#oidcng-server)

This project uses Spring Boot and Maven. To run locally, type:

`mvn spring-boot:run -Drun.jvmArguments="-Dspring.profiles.active=dev"`

When developing, it's convenient to just execute the applications main-method. The `dev` profile uses a fake authorization
to bypass the redirect to EB.

### [Endpoints](#endpoint)

Discovery Endpoint describing the OIDC supported options. 
The content is from [https://github.com/OpenConext/OpenConext-deploy/blob/master/roles/oidcng/templates/openid-configuration.json.j2](https://github.com/OpenConext/OpenConext-deploy/blob/master/roles/oidcng/templates/openid-configuration.json.j2)
```
https://oidcng.test2.surfconext.nl/oidc/.well-known/openid-configuration
```
Generate a Secret Key Set for encryption / decryption of the user claims in the access token.
The output is used in ansible to create the file [https://github.com/OpenConext/OpenConext-oidcng/blob/master/src/main/resources/secret_keyset.json](https://github.com/OpenConext/OpenConext-oidcng/blob/master/src/main/resources/secret_keyset.json)
```
https://oidcng.test2.surfconext.nl/oidc/generate-secret-key-set
```
The public certificate that RP's can use to validate the signed JWT. This endpoint is also configured in the `.well-known/openid-configuration` endpoint. 
```
https://oidcng.test2.surfconext.nl/oidc/certs
```

### [cUrl](#curl-testing)

When you have the oidcng server running locally with the `dev` profile you can use cUrl to test the different endpoints.

Note that this only works because of the `dev` profile where there is pre-authenticated user provided by the `FakeSamlAuthenticationFilter`.

First obtain an authorization code:

```
curl -i  "http://localhost:8080/oidc/authorize?response_type=code&client_id=mock-sp&scope=openid&redirect_uri=http://localhost:8091/redirect"
```

This will output the following:

```bash
HTTP/1.1 302 
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Set-Cookie: SESSION=MTYzNjU2OTItZmFiMC00YWU0LWFlOTAtZjA2MDBhYzc1NTFi; Path=/; HttpOnly
Location: http://localhost:8091/redirect?code=x2F7TN56A9cB
Content-Language: en-NL
Content-Length: 0
Date: Wed, 15 May 2019 11:23:39 GMT
```

Save the code in the query parameter of the location response header in a variable (use the code of your response and not this example code):

`export code=x2F7TN56A9cB`

And then exchange the code for an access token:

```
curl -X POST -u mock-sp:secret -d "grant_type=authorization_code&code=${code}&redirect_uri=http://localhost:8091/redirect" http://localhost:8080/oidc/token | jq .
```

This will return the access_token and id_token.

```json
{
  "access_token": "eyJraWQiOiJvaWRjIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhdWQiOiJodHRwQFwvXC9tb2NrLXNwIiwic3ViIjoiaHR0cEBcL1wvbW9jay1zcCIsIm5iZiI6MTU1NzkxOTUxMSwiaXNzIjoiaHR0cHM6XC9cL29yZy5vcGVuY29uZXh0Lm9pZGMubmciLCJjbGFpbXMiOiJBU2lFMHNCM2tUemlhWms0ekEzTVRobm0rVWlwditOWHA5bmRQNWF6QUZQOTdRQzgrVEk1YlwvXC9sK3ZGVllNbUVBVWxXVlJnXC95ZjhGZHVubnZUOUUxUnFieFdkbXBwNUpMSlE0S0hpclhBMldCeHVVVHpRRGNMVUp5MWhpa2l5UDFXaXhKTzJJcDZNYk85MkdDXC9nOG1COUh1elc2NXpGaGdoS010Vkc4d3Q1cVwvY0JxMEl6UUY5MjdENWJkVEgrS1pBZUpLT3FxUHpmankwZDJcL3pzN0toeVllalRmQlEzV2N2c2VcL2NcLzdlak45S202eDAxOVY4dUVEUVc0TkF4T2J3dmFlMjdsdXBJR013U1hGRnQrcHZMTFVCbjNqQjlrQTc4cWVlbXZDUEtrelRQUVFnb1RPVEx3T2I1dCtGYTVoaU1MVWhudlhyWFAwSWJTMWVqeTI4UjNNclZ0TUxyRGFmZ3UxbVFmd3h3WFMwR1ZYSkhGTTUwSmYrdWFlQXpBZXd6UUxqUnFPaG1WdGJNcFhsU3dpcjB4Zlc5dkttQ1ZiN2NGVUhjbWFZRmw4MWhGOUk2bE43cklsWjdmMWJPYTVIQ0M3NnliZmNrUG1GVkpiczMwUk9yV0V1QnQ0UUlcLzdyQjdZTWUwTUp5R3F5R1p2YWhMdElsXC92T1wvMkdGODJZUEtwRCsxUHU0ZndrS3JTYkFDSGx5OXN2cmRiXC9EMU1scjk1Yk5tb3UrTnp2NnJ6OTRHXC9lNHArZVoxN1pxS0JEMVgrUGQ5bERkTTZGalV3QlBEWVJNdUVOQTY5WHdkZnVGZzRlYmRwRXJZSkQrUVRlOExqUUl5U1ZWNXh4ZjVVRG5UWXg2RXhXTHVSY1JWbVVHc3B1TUV2WjdWZFFMbUhiZk5YWk9cL3hQbHJUd05xZWRVbkw5c1N3cENDM3hNdEttN01ZZVFSZHlCUUVPT1N1Ym84Y2JlMXFJVXJvRDVCcXlkXC9SWTRJajg1V2d1VDVBS1hWQXgxUXdCRFI2STR0cXpMZm1QNG9MU25Rd0NtWlJvelpDek5TNkxPbVd3Z3VoRGZEV0F1WmtnYmxPdFZabG9Xam1wVFA1cjdvaWNnTDlKc3B1RTRsOVV5a2ZWcDhzOU1sNjlvYlloRG1oUEp3cHpSZEZNNlRobEhUOElcL2hBMjZzZEFyYlpGRmpYUCtCc1A4TWpzbE5YZ1VMV2ZDRENyZWVvNEJQSVN3bnFQNExSSmVDUGlBemIxVlRYOHhyZ28wSXNkeDZPcEhsWVwvaXdLMTBSQUwwUUF3R3VQVXdoRHBNN1RXRUtNXC8iLCJleHAiOjQxMDI0NDg0MDAsImNsYWltX2tleV9pZCI6Im9pZGMiLCJpYXQiOjQxMDI0NDQ4MDAsImp0aSI6IjZmZWZjYzNhLTFkOTctNDgwZS1hN2I5LTFlZjFkZGJkOWViMCJ9.pWZb0YEvrl-fYjztOQQ5nMb_c7_RS4PBY-Sj1KKG-I1H5W6ywQg8CbfbnOohjb5nIv8mcA5GYKbTH7RtVjEq2r5511BCWg-lND72ZF2MzCc15-wZSAjn-uWUEPEjd9mf14Fc_2CgYXb2i4tK2xfRi3QXXFvnXPw6XvO_YKKH1W3wZBndMtiM2cfXS5pfMApr4jor9ULCXHBviFFttBh_2VLh8y1kw4OG3hXxvUMVrrjakP3ptoy3LYjjHcp04kB2BtEC3ztvU3KxC1dZefgeQaZcxMNZNWbhLIat2WRkuY9s37Y8VJY8L74l3H0ahRLM3_SkcKAmbpCcmlRBUGO9sg",
  "refresh_token": "16f13061-21fc-4e85-bd65-620c470f9cb8",
  "id_token": "eyJraWQiOiJvaWRjIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhdWQiOiJodHRwQFwvXC9tb2NrLXNwIiwic3ViIjoiY2I2ZTQwYjctMWUwNy00OGQwLWEzMmMtNGM5OTRkZjhhZmQ4IiwibmJmIjoxNTU3OTE5NTExLCJpc3MiOiJodHRwczpcL1wvb3JnLm9wZW5jb25leHQub2lkYy5uZyIsImV4cCI6NDEwMjQ0ODQwMCwiaWF0Ijo0MTAyNDQ0ODAwLCJqdGkiOiIxNjgwNDY0Zi1kYzc1LTRjMjAtYjAzNC0zOGM5NjdkNjQxYWIifQ.Tz28mRbbf8ac07dqbdvbWmlOVzENRkFDP90pyOPB617MOwSmDReO4HO7pE-Evl6HdALTCUGwfJkO3K-WB41_N_BYFQwTMizMUS5jprtxDiUqvBcF9jsa2tUzECnMEdast3IydQ1PRPvpLCwQYmo9K3FTQvsfjg062T4nh2ZctmMjwmOyl5FHKaPX79gwtUhiAmuL_-dsyeY1P6Tox5y8IKPlfVX3ZNGlDX9ImnA5_EOxnKtjR-B82YRhrNj_xGAiIpl66EGO3HMZx9WTYN2y22EJWTLyuJnmYq72VSLkQWppybdXh1kjm9Q0B4hNuNrJyeQ-hGoQdkE2lVB8tkpVDQ",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Save the access_token in a variable:

```
export access_token=eyJraWQiOiJvaWRjIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhdWQiOiJodHRwQFwvXC9tb2NrLXNwIiwic3ViIjoiaHR0cEBcL1wvbW9jay1zcCIsIm5iZiI6MTU1NzkxOTUxMSwiaXNzIjoiaHR0cHM6XC9cL29yZy5vcGVuY29uZXh0Lm9pZGMubmciLCJjbGFpbXMiOiJBU2lFMHNCM2tUemlhWms0ekEzTVRobm0rVWlwditOWHA5bmRQNWF6QUZQOTdRQzgrVEk1YlwvXC9sK3ZGVllNbUVBVWxXVlJnXC95ZjhGZHVubnZUOUUxUnFieFdkbXBwNUpMSlE0S0hpclhBMldCeHVVVHpRRGNMVUp5MWhpa2l5UDFXaXhKTzJJcDZNYk85MkdDXC9nOG1COUh1elc2NXpGaGdoS010Vkc4d3Q1cVwvY0JxMEl6UUY5MjdENWJkVEgrS1pBZUpLT3FxUHpmankwZDJcL3pzN0toeVllalRmQlEzV2N2c2VcL2NcLzdlak45S202eDAxOVY4dUVEUVc0TkF4T2J3dmFlMjdsdXBJR013U1hGRnQrcHZMTFVCbjNqQjlrQTc4cWVlbXZDUEtrelRQUVFnb1RPVEx3T2I1dCtGYTVoaU1MVWhudlhyWFAwSWJTMWVqeTI4UjNNclZ0TUxyRGFmZ3UxbVFmd3h3WFMwR1ZYSkhGTTUwSmYrdWFlQXpBZXd6UUxqUnFPaG1WdGJNcFhsU3dpcjB4Zlc5dkttQ1ZiN2NGVUhjbWFZRmw4MWhGOUk2bE43cklsWjdmMWJPYTVIQ0M3NnliZmNrUG1GVkpiczMwUk9yV0V1QnQ0UUlcLzdyQjdZTWUwTUp5R3F5R1p2YWhMdElsXC92T1wvMkdGODJZUEtwRCsxUHU0ZndrS3JTYkFDSGx5OXN2cmRiXC9EMU1scjk1Yk5tb3UrTnp2NnJ6OTRHXC9lNHArZVoxN1pxS0JEMVgrUGQ5bERkTTZGalV3QlBEWVJNdUVOQTY5WHdkZnVGZzRlYmRwRXJZSkQrUVRlOExqUUl5U1ZWNXh4ZjVVRG5UWXg2RXhXTHVSY1JWbVVHc3B1TUV2WjdWZFFMbUhiZk5YWk9cL3hQbHJUd05xZWRVbkw5c1N3cENDM3hNdEttN01ZZVFSZHlCUUVPT1N1Ym84Y2JlMXFJVXJvRDVCcXlkXC9SWTRJajg1V2d1VDVBS1hWQXgxUXdCRFI2STR0cXpMZm1QNG9MU25Rd0NtWlJvelpDek5TNkxPbVd3Z3VoRGZEV0F1WmtnYmxPdFZabG9Xam1wVFA1cjdvaWNnTDlKc3B1RTRsOVV5a2ZWcDhzOU1sNjlvYlloRG1oUEp3cHpSZEZNNlRobEhUOElcL2hBMjZzZEFyYlpGRmpYUCtCc1A4TWpzbE5YZ1VMV2ZDRENyZWVvNEJQSVN3bnFQNExSSmVDUGlBemIxVlRYOHhyZ28wSXNkeDZPcEhsWVwvaXdLMTBSQUwwUUF3R3VQVXdoRHBNN1RXRUtNXC8iLCJleHAiOjQxMDI0NDg0MDAsImNsYWltX2tleV9pZCI6Im9pZGMiLCJpYXQiOjQxMDI0NDQ4MDAsImp0aSI6IjZmZWZjYzNhLTFkOTctNDgwZS1hN2I5LTFlZjFkZGJkOWViMCJ9.pWZb0YEvrl-fYjztOQQ5nMb_c7_RS4PBY-Sj1KKG-I1H5W6ywQg8CbfbnOohjb5nIv8mcA5GYKbTH7RtVjEq2r5511BCWg-lND72ZF2MzCc15-wZSAjn-uWUEPEjd9mf14Fc_2CgYXb2i4tK2xfRi3QXXFvnXPw6XvO_YKKH1W3wZBndMtiM2cfXS5pfMApr4jor9ULCXHBviFFttBh_2VLh8y1kw4OG3hXxvUMVrrjakP3ptoy3LYjjHcp04kB2BtEC3ztvU3KxC1dZefgeQaZcxMNZNWbhLIat2WRkuY9s37Y8VJY8L74l3H0ahRLM3_SkcKAmbpCcmlRBUGO9sg
```

Now you can ask the server to return the information stored with this access_token by calling the introspect endpoint (note that this endpoint is only for resource servers):

```
curl -u mock-sp:secret -H "Content-Type: application/x-www-form-urlencoded" -X POST "http://localhost:8080/oidc/introspect?token=${access_token}" | jq .
```

This will return:

```json
{
  "sub": "cb6e40b7-1e07-48d0-a32c-4c994df8afd8",
  "updated_at": 1557919511,
  "scope": "openid",
  "iss": "https://org.openconext.oidc.ng",
  "active": true,
  "unspecifiedNameId": "urn:collab:person:example.com:admin",
  "authenticatingAuthority": "http://mock-idp",
  "exp": 1557923111,
  "token_type": "Bearer",
  "client_id": "mock-sp"
}
```

Use the same access_token to call the user_info endpoint:

```
curl -H "Authorization: Bearer ${access_token}" -H "Content-type: application/json" http://localhost:8080/oidc/userinfo | jq .
```

This will return all the information about the user. This endpoint is for Relaying Parties.

```json
{
  "preferred_username": "Johnny D.",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "nickname": "Johhny",
  "email": "john.doe@example.org",
  "phone_number": "0612345678",
  "sub": "FF208708-6443-48DB-904F-E0D0BA62B38D",
  "schac_home_organization": "schac_home",
  "edu_person_principal_name": "edu_person_principal_name",
  "edu_person_targeted_id": "edu_person_targeted_id",
  "edu_person_affiliations": [
    "edu_person_affiliation"
  ],
  "updated_at": 1557919511
}
```
### [client JWT](#client-jwt)
The authorization endpoint also accepts signed JWT's from the RP. To verify the signature the signing certificate is required. This can be configured in Manage.

For testing purposes a keypair can be generated:
```
openssl genrsa -out "oidc.key" 2048
openssl req -new -key "oidc.key" -out "oidc.csr"
openssl x509 -req -sha256 -days 1095 -in "oidc.csr" -signkey "oidc.key" -out "oidc.crt"
cat oidc.crt |head -n -1 |tail -n +2 | tr -d '\n'
```
On a Mac you can issue the same commands with `ghead` instead of `head` after you install `coreutils`:
```
cat oidc.crt |ghead -n -1 |tail -n +2 | tr -d '\n'
```
### [Key rollover](#key-rollover)
The OpenID Connect Provider had administrator endpoints to rollover both the signing keys as the symmetric keys. The signing keys are used to
sign and verify the JWT tokens. The symmetric keys are used to encrypt and decrypt the user claims in the access_token.

To rollover the signing key and clean up unreferenced signing keys:
```
curl -u manage:secret "http://localhost:8080/manage/force-signing-key-rollover"
```
To rollover the symmetric key and clean up unreferenced symmetric keys:
```
curl -u manage:secret "http://localhost:8080/manage/force-symmetric-key-rollover"
```
