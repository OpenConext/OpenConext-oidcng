# OpenConext-oidcng
[![Build Status](https://travis-ci.org/OpenConext/OpenConext-oidcng.svg?branch=master)](https://travis-ci.org/OpenConext/OpenConext-oidcng)
[![codecov.io](https://codecov.io/github/OpenConext/OpenConext-oidcng/coverage.svg)](https://codecov.io/github/OpenConext/OpenConext-oidcng)

OpenID Connect - SAML proxy

## [Getting started](#getting-started)

### [System Requirements](#system-requirements)

- Java 8
- Maven 3.x
- MongoDB 4.0.x

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
Generate a Master Secret Key Set. This master key encrypts both the JWT signing keys as the symmetric keys that are used to encrypt/decrypt the claims in the access_token
The output is used in ansible to create the file [https://github.com/OpenConext/OpenConext-oidcng/blob/master/src/main/resources/secret_keyset.json](https://github.com/OpenConext/OpenConext-oidcng/blob/master/src/main/resources/secret_keyset.json)
```
https://oidcng.test2.surfconext.nl/oidc/generate-secret-key-set
```
If you have started the application before adding the new keyset, you have to remove the existing signing and symmetric keys from the mongo database. Run these two commands on the mongo prompt:
```
db.symmetric_keys.remove({})
db.signing_keys.remove({})
```
You can also use this Java binary to generate a keyset to use before starting oidcng [https://build.openconext.org/repository/public/releases/org/openconext/crypto/1.0.0/crypto-1.0.0-shaded.jar](https://build.openconext.org/repository/public/releases/org/openconext/crypto/1.0.0/crypto-1.0.0-shaded.jar)

The public certificate that RP's can use to validate the signed JWT. This endpoint is also configured in the `.well-known/openid-configuration` endpoint.
```
https://oidcng.test2.surfconext.nl/oidc/certs
```

### [cUrl](#curl-testing)

When you have the oidcng server running locally with the `dev` profile you can use cUrl to test the different endpoints.

Note that this only works because of the `dev` profile where there is pre-authenticated user provided by the `FakeSamlAuthenticationFilter`. You will also need to have the original `secret_keyset.json` in place to make this work.

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
  "refresh_token": "eyJraWQiOiJrZXlfMjAyMV8wM18xOF8xMl80OF8zOV85ODEiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJtb2NrLXNwIiwic3ViIjoibW9jay1zcCIsIm5iZiI6MTYxNjA2ODIyNSwiaXNzIjoiaHR0cHM6XC9cL29yZy5vcGVuY29uZXh0LmxvY2FsLm9pZGMubmciLCJjbGFpbXMiOiJBUzZqNW9UU2hXMTlJcXQ5RDRTQ0xDbVVIMDhDRFZ0ejdPZUZXS3VTcmFYOGgzMGd5bmp2bjVXXC90QU01VzAxbDBvcGI1ZUVVdVd0TFl0c21QbHUyM2l2dUNcLzhNMDRiOFVySjk3SzJYb1A3bjFMNG1jTklXcjVmaTRJODAzYm1ZZmxMSTdyOTFwZkZYb3FucEZueXpDNkdvUnA5alZNRUFzM2N1VDlKSHpFazhRN0dBSUU0TCthOEd6QkZ3MzdTVWIxS1UxXC9ROGF5T1VsUUJjeENUUFZIbERVTUdVdW5LMlF1XC9KTElvT3M0cEF0Vm10RjlJSmdrTzlnM0h6bjRVWXR1WGdFc3dLY1FPOWRlNU5UTVdXZEJiaEVzcHRrMWxLeVwvU25CUjlQa3NuNDY2aEs2QzlYeXRPZ3E3SUlNVmZLXC9wd0JUeFwvMU9udHd4UWRFTHBxZTRkSmlldlZkTU93UWNnRGIzTnVQSHcxRTJDMUVLZ3ZwZVM2Z2d1MkE5N1Z4YkxhZkJwTG00TVJaUHlGNTRNbnU0Z1BydFJKUldNWkJzakhCNkw2ZEh6YUloZElNUWJQSnA4VUV0TExCSkJNZ2tGWTlGTmNKYkZZRDlWQTJ4RDQ2WjA0azNubmV2aU1Kb1JKTVlsdHhhWHVhYzRuKzFaRFVaZXVYbnpXdnl0TFo3M1Jnek9DV21SRGtqdDQ4bHhuVnNHWm5UbDVSN3FCd2RYYWJ6MXF0OUI5eTNEVEZvbVRHdGRqNmVRQU9kYlNLVk5FYm5PVFNxc1B0emVlbWFxVEdvbzAxV3pKMGpJMmdVeHpKTFNQOXEycFp4VHh3XC9PNnFtcVRBVWdtQm5kbnBTd3lGcEx6NDVEZklSYWhUK0RJeThJUUNSRU1IYmhqZzdIY3B4M0xLdkF1anl4dzN6YlNmOWhhXC9WQ1hpUlY3S2xUZXVvcDBpYXpvZGRCUGMrY0hNdTczTUlZTGpTZ1hENkQwMWdJVDJzXC9BUlRzTFF6OGh6ZnpzTjZibGtib3cybmhFRk5xTlhUZVZWNU9RNEhJVmpMTTdYK3MyZ05KWXFqb1ZNQjhaSXdJRXJETkU4UktscUZYaWZvMHhWSUZWaStkWmJpMG45Y3lncFNmd1l1Z1lBb2ZcL1RTU08xdnBHNTFSQm9vRFErUkk0WjN6eTVXczQ1YlFzYVZVY05oNXRxZDV5K28xcXFmdDdldVwvbnAzSXFibmZ6c2JZQzczMzd5bjM0cjJITFB4cnZoN0xpd0JjNzJFYytibTF6WElzZndTTWpnMkt0U3pjNUJ1c3I4Wmc9PSIsImV4cCI6NDEwMjQ0ODQwMCwiY2xhaW1fa2V5X2lkIjoiNzgyNDkzMzE2IiwiaWF0Ijo0MTAyNDQ0ODAwLCJqdGkiOiIyNmRiNDZjNi1hNjMwLTQzMGUtOWUyYS0yNDJiNzg5YzViZTYifQ.LLliKefzqznnNjlCupeV2I4HlP-CxDUSPAYysTf7DfxK3gPv-kLT7jRMcGRabaABDw0Bc23_xKjDWFdMqgFerYFUi7Awy981cPz7lavBvzF045B7z-GlfDo4plSfsRpW7-a4tyTlS0coA4IO86vb8pV0Hihudb6wzL3DQ9DlWExWWkNmDxufXZ-wiqacWmvCnctBarvaHVbESxE68ZDTMLZwX7WxtU6xTfBkuF-jTf43xQ0NLa_nLwrksjMd5J0ubMM4pw_MHpeNOJm_VUFpQ6vWafsGMHbSalN862g9tmt9v4qdT-5ql99ipYHRowHb8j0YAD5iKqoQ8lbXO7ZQMQ",
  "id_token": "eyJraWQiOiJvaWRjIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhdWQiOiJodHRwQFwvXC9tb2NrLXNwIiwic3ViIjoiY2I2ZTQwYjctMWUwNy00OGQwLWEzMmMtNGM5OTRkZjhhZmQ4IiwibmJmIjoxNTU3OTE5NTExLCJpc3MiOiJodHRwczpcL1wvb3JnLm9wZW5jb25leHQub2lkYy5uZyIsImV4cCI6NDEwMjQ0ODQwMCwiaWF0Ijo0MTAyNDQ0ODAwLCJqdGkiOiIxNjgwNDY0Zi1kYzc1LTRjMjAtYjAzNC0zOGM5NjdkNjQxYWIifQ.Tz28mRbbf8ac07dqbdvbWmlOVzENRkFDP90pyOPB617MOwSmDReO4HO7pE-Evl6HdALTCUGwfJkO3K-WB41_N_BYFQwTMizMUS5jprtxDiUqvBcF9jsa2tUzECnMEdast3IydQ1PRPvpLCwQYmo9K3FTQvsfjg062T4nh2ZctmMjwmOyl5FHKaPX79gwtUhiAmuL_-dsyeY1P6Tox5y8IKPlfVX3ZNGlDX9ImnA5_EOxnKtjR-B82YRhrNj_xGAiIpl66EGO3HMZx9WTYN2y22EJWTLyuJnmYq72VSLkQWppybdXh1kjm9Q0B4hNuNrJyeQ-hGoQdkE2lVB8tkpVDQ",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Save the access_token and the response_token in variables:

```
export access_token=eyJraWQiOiJvaWRjIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJhdWQiOiJodHRwQFwvXC9tb2NrLXNwIiwic3ViIjoiaHR0cEBcL1wvbW9jay1zcCIsIm5iZiI6MTU1NzkxOTUxMSwiaXNzIjoiaHR0cHM6XC9cL29yZy5vcGVuY29uZXh0Lm9pZGMubmciLCJjbGFpbXMiOiJBU2lFMHNCM2tUemlhWms0ekEzTVRobm0rVWlwditOWHA5bmRQNWF6QUZQOTdRQzgrVEk1YlwvXC9sK3ZGVllNbUVBVWxXVlJnXC95ZjhGZHVubnZUOUUxUnFieFdkbXBwNUpMSlE0S0hpclhBMldCeHVVVHpRRGNMVUp5MWhpa2l5UDFXaXhKTzJJcDZNYk85MkdDXC9nOG1COUh1elc2NXpGaGdoS010Vkc4d3Q1cVwvY0JxMEl6UUY5MjdENWJkVEgrS1pBZUpLT3FxUHpmankwZDJcL3pzN0toeVllalRmQlEzV2N2c2VcL2NcLzdlak45S202eDAxOVY4dUVEUVc0TkF4T2J3dmFlMjdsdXBJR013U1hGRnQrcHZMTFVCbjNqQjlrQTc4cWVlbXZDUEtrelRQUVFnb1RPVEx3T2I1dCtGYTVoaU1MVWhudlhyWFAwSWJTMWVqeTI4UjNNclZ0TUxyRGFmZ3UxbVFmd3h3WFMwR1ZYSkhGTTUwSmYrdWFlQXpBZXd6UUxqUnFPaG1WdGJNcFhsU3dpcjB4Zlc5dkttQ1ZiN2NGVUhjbWFZRmw4MWhGOUk2bE43cklsWjdmMWJPYTVIQ0M3NnliZmNrUG1GVkpiczMwUk9yV0V1QnQ0UUlcLzdyQjdZTWUwTUp5R3F5R1p2YWhMdElsXC92T1wvMkdGODJZUEtwRCsxUHU0ZndrS3JTYkFDSGx5OXN2cmRiXC9EMU1scjk1Yk5tb3UrTnp2NnJ6OTRHXC9lNHArZVoxN1pxS0JEMVgrUGQ5bERkTTZGalV3QlBEWVJNdUVOQTY5WHdkZnVGZzRlYmRwRXJZSkQrUVRlOExqUUl5U1ZWNXh4ZjVVRG5UWXg2RXhXTHVSY1JWbVVHc3B1TUV2WjdWZFFMbUhiZk5YWk9cL3hQbHJUd05xZWRVbkw5c1N3cENDM3hNdEttN01ZZVFSZHlCUUVPT1N1Ym84Y2JlMXFJVXJvRDVCcXlkXC9SWTRJajg1V2d1VDVBS1hWQXgxUXdCRFI2STR0cXpMZm1QNG9MU25Rd0NtWlJvelpDek5TNkxPbVd3Z3VoRGZEV0F1WmtnYmxPdFZabG9Xam1wVFA1cjdvaWNnTDlKc3B1RTRsOVV5a2ZWcDhzOU1sNjlvYlloRG1oUEp3cHpSZEZNNlRobEhUOElcL2hBMjZzZEFyYlpGRmpYUCtCc1A4TWpzbE5YZ1VMV2ZDRENyZWVvNEJQSVN3bnFQNExSSmVDUGlBemIxVlRYOHhyZ28wSXNkeDZPcEhsWVwvaXdLMTBSQUwwUUF3R3VQVXdoRHBNN1RXRUtNXC8iLCJleHAiOjQxMDI0NDg0MDAsImNsYWltX2tleV9pZCI6Im9pZGMiLCJpYXQiOjQxMDI0NDQ4MDAsImp0aSI6IjZmZWZjYzNhLTFkOTctNDgwZS1hN2I5LTFlZjFkZGJkOWViMCJ9.pWZb0YEvrl-fYjztOQQ5nMb_c7_RS4PBY-Sj1KKG-I1H5W6ywQg8CbfbnOohjb5nIv8mcA5GYKbTH7RtVjEq2r5511BCWg-lND72ZF2MzCc15-wZSAjn-uWUEPEjd9mf14Fc_2CgYXb2i4tK2xfRi3QXXFvnXPw6XvO_YKKH1W3wZBndMtiM2cfXS5pfMApr4jor9ULCXHBviFFttBh_2VLh8y1kw4OG3hXxvUMVrrjakP3ptoy3LYjjHcp04kB2BtEC3ztvU3KxC1dZefgeQaZcxMNZNWbhLIat2WRkuY9s37Y8VJY8L74l3H0ahRLM3_SkcKAmbpCcmlRBUGO9sg
export refresh_token=eyJraWQiOiJrZXlfMjAyMV8wM18xOF8xMl80OF8zOV85ODEiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJtb2NrLXNwIiwic3ViIjoibW9jay1zcCIsIm5iZiI6MTYxNjA2ODIyNSwiaXNzIjoiaHR0cHM6XC9cL29yZy5vcGVuY29uZXh0LmxvY2FsLm9pZGMubmciLCJjbGFpbXMiOiJBUzZqNW9UU2hXMTlJcXQ5RDRTQ0xDbVVIMDhDRFZ0ejdPZUZXS3VTcmFYOGgzMGd5bmp2bjVXXC90QU01VzAxbDBvcGI1ZUVVdVd0TFl0c21QbHUyM2l2dUNcLzhNMDRiOFVySjk3SzJYb1A3bjFMNG1jTklXcjVmaTRJODAzYm1ZZmxMSTdyOTFwZkZYb3FucEZueXpDNkdvUnA5alZNRUFzM2N1VDlKSHpFazhRN0dBSUU0TCthOEd6QkZ3MzdTVWIxS1UxXC9ROGF5T1VsUUJjeENUUFZIbERVTUdVdW5LMlF1XC9KTElvT3M0cEF0Vm10RjlJSmdrTzlnM0h6bjRVWXR1WGdFc3dLY1FPOWRlNU5UTVdXZEJiaEVzcHRrMWxLeVwvU25CUjlQa3NuNDY2aEs2QzlYeXRPZ3E3SUlNVmZLXC9wd0JUeFwvMU9udHd4UWRFTHBxZTRkSmlldlZkTU93UWNnRGIzTnVQSHcxRTJDMUVLZ3ZwZVM2Z2d1MkE5N1Z4YkxhZkJwTG00TVJaUHlGNTRNbnU0Z1BydFJKUldNWkJzakhCNkw2ZEh6YUloZElNUWJQSnA4VUV0TExCSkJNZ2tGWTlGTmNKYkZZRDlWQTJ4RDQ2WjA0azNubmV2aU1Kb1JKTVlsdHhhWHVhYzRuKzFaRFVaZXVYbnpXdnl0TFo3M1Jnek9DV21SRGtqdDQ4bHhuVnNHWm5UbDVSN3FCd2RYYWJ6MXF0OUI5eTNEVEZvbVRHdGRqNmVRQU9kYlNLVk5FYm5PVFNxc1B0emVlbWFxVEdvbzAxV3pKMGpJMmdVeHpKTFNQOXEycFp4VHh3XC9PNnFtcVRBVWdtQm5kbnBTd3lGcEx6NDVEZklSYWhUK0RJeThJUUNSRU1IYmhqZzdIY3B4M0xLdkF1anl4dzN6YlNmOWhhXC9WQ1hpUlY3S2xUZXVvcDBpYXpvZGRCUGMrY0hNdTczTUlZTGpTZ1hENkQwMWdJVDJzXC9BUlRzTFF6OGh6ZnpzTjZibGtib3cybmhFRk5xTlhUZVZWNU9RNEhJVmpMTTdYK3MyZ05KWXFqb1ZNQjhaSXdJRXJETkU4UktscUZYaWZvMHhWSUZWaStkWmJpMG45Y3lncFNmd1l1Z1lBb2ZcL1RTU08xdnBHNTFSQm9vRFErUkk0WjN6eTVXczQ1YlFzYVZVY05oNXRxZDV5K28xcXFmdDdldVwvbnAzSXFibmZ6c2JZQzczMzd5bjM0cjJITFB4cnZoN0xpd0JjNzJFYytibTF6WElzZndTTWpnMkt0U3pjNUJ1c3I4Wmc9PSIsImV4cCI6NDEwMjQ0ODQwMCwiY2xhaW1fa2V5X2lkIjoiNzgyNDkzMzE2IiwiaWF0Ijo0MTAyNDQ0ODAwLCJqdGkiOiIyNmRiNDZjNi1hNjMwLTQzMGUtOWUyYS0yNDJiNzg5YzViZTYifQ.LLliKefzqznnNjlCupeV2I4HlP-CxDUSPAYysTf7DfxK3gPv-kLT7jRMcGRabaABDw0Bc23_xKjDWFdMqgFerYFUi7Awy981cPz7lavBvzF045B7z-GlfDo4plSfsRpW7-a4tyTlS0coA4IO86vb8pV0Hihudb6wzL3DQ9DlWExWWkNmDxufXZ-wiqacWmvCnctBarvaHVbESxE68ZDTMLZwX7WxtU6xTfBkuF-jTf43xQ0NLa_nLwrksjMd5J0ubMM4pw_MHpeNOJm_VUFpQ6vWafsGMHbSalN862g9tmt9v4qdT-5ql99ipYHRowHb8j0YAD5iKqoQ8lbXO7ZQMQ
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
You can get a new refresh_token by using the stored refresh_token:
```
curl -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d "grant_type=refresh_token&client_id=mock-sp&client_secret=secret&refresh_token=${refresh_token}" 'http://localhost:8080/oidc/token' | jq .
```
Which will return new tokens:
```json
{
  "access_token": "eyJraWQiOiJrZXlfMjAyMV8wM18xOF8xMl80OF8zOV85ODEiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOlsibW9jay1zcCIsInJlc291cmNlLXNlcnZlci1wbGF5Z3JvdW5kLWNsaWVudCJdLCJzdWIiOiJtb2NrLXNwIiwibmJmIjoxNjE2MDY4NDU3LCJzY29wZSI6Im9wZW5pZCIsImlzcyI6Imh0dHBzOlwvXC9vcmcub3BlbmNvbmV4dC5sb2NhbC5vaWRjLm5nIiwiY2xhaW1zIjoiQVM2ajVvU1VVOVV6OW9BckVPVmg1NGtTUk5rK3VNQU9lcHpVeXBiOTNWRnl5SnBRMFgxTk9qYVpvY29zWXpTUk1pQmx4SkJjZ1FXZjJzMWxIWUhoUW5Zb1ZKSTY1eXhhemxENjdUSVlZZG9YSU9MbXRLRlVUK1d6dFl2SlVDMnpWK0lUY2dJamFDZFZDZUxqTHdhcWkzZ1wvd1FhYnplbW5GRnpzZm55bnJ1TER0cXdnZGdcLzlTNEd4eHNhSFRaRkJxMVlZM1I2THlxQkFIanhhNXhRbWxOaXJXUjhQVStqM2FrNXI4SWdJSjRUYk94YWxvbnBqXC9wQVVveEpDdURkNVB0dHRiMlJqQm5UeUtVUU1hazBXTVI2MzRiT0h1XC9XZjRYUlQrVmI4bFY5c0R2endHVEc2czBuXC82Qk9vOGJ5ZFpcL1IzQVc4ZVl3TEpvMXJqWlk2WVJ2YUpSRHNZYU5rMU5RakpcL3g2dmZJRFR6Y0JyZnNxaDVBcFlWeTVNcnBOcktON0V2U1RWaFVlSEZIZzZ2T0xKRWpCaXdFSkh0cHNRc1RNZW9lQitvOWppREYrYkxkaVRoQ29VNWRuR1M4WElydVBvSUp2OTRBRkhNaEJQR0ZwV1FpV29BM0h6S0tsUkpmSW1WSVFRXC9LOFVVK0xtemF0dHZkYThpSE1kRjZnb2pOVHZ4YThCN2RQVnAwU1NmSE9CMStDNEIzSURya3JQdjhHYXB5NmRuaE5vTXZJQVpVWnVxXC80SnJwRTFUeGttYlwvR3E4RGlpVUV3cmU0b0RJSmtoZFI2R29PekJTd0lWSW1VQ2NXWlFDeTB3TGcwODZEQVVxTXZzZElWWmNyQjJ1eXBnUE9CaWNqbktlWlZyb1hxY0ppR0cxOUYybWtMaGtsR2tzT25YMEtFZXB2XC9IZEdtbHFLcXVUeE1MQ2tkUmRsNm52d1NFb3NZZUZJSG9Lck1McUZEa0ZqNGIxNENpOTdDaHBWME1CaUhCUDJqbVVtNmtXRW9OSEw2VDRkZnBPVk5MVWdiWWNaZXNUYzcwRlh5STllZDhQV3MyOHh2amdpV0FlNDlyanlQbSt2ZEs0eXp1amFaclJwYStWT3J3bFczVWlVaXR2dnl1XC9RYWswNFVOU3duaGNNYmJxYVRqWmtEOUtnVXRpREtLWnVnRENcL2VrampCTDIzWXJDQ0RmWHhaTVJGek45RUNtc25KUUpQaER3OWdPRFBiZVhMUWU2R29wY2V3SmU4d244QWc3RUd4V0g3blVON2xQTzJ2OFd1S2xKY0pmcFwvM2F1MjNXRlE9PSIsImV4cCI6NDEwMjQ0ODQwMCwiY2xhaW1fa2V5X2lkIjoiNzgyNDkzMzE2IiwiaWF0Ijo0MTAyNDQ0ODAwLCJqdGkiOiJiYjI0MTk0Ni00NWU0LTRlNWQtODI3Yy01YmI5YzE4OGNkNzgifQ.FkXLfl8frUd0c3e9-pu49_7OvapqXeFKxWcBBZjfgmXNXEnr-euJ69CTwEWd0Gf32BcAidUBjlT3Rkbxi6Txmo_FmBQEnoHzSP5yNfubX0CBgwRfAzmj8o7Qvj_pO-bZ_cjC_NOKbqTU5UIELvKPO_BX_aLXnaXkY_rGrrpGEILelFwed1SvPq5O98oT9XryN8ARfkJ-IDWWUP3Ycacvltg-bHeQjG9-htMl5Oh7l1jcT8Q9O08GV2Q7J02FcndGwjfi8F3HtMymc2gFSwJgzbUYGwKfyp77dCQqOZX2WuP_rfc3a5G0eDYcDThyWab7DJDvdqWq0WpwX85jK8g0rw",
  "token_type": "Bearer",
  "refresh_token": "eyJraWQiOiJrZXlfMjAyMV8wM18xOF8xMl80OF8zOV85ODEiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJtb2NrLXNwIiwic3ViIjoibW9jay1zcCIsIm5iZiI6MTYxNjA2ODQ1NywiaXNzIjoiaHR0cHM6XC9cL29yZy5vcGVuY29uZXh0LmxvY2FsLm9pZGMubmciLCJjbGFpbXMiOiJBUzZqNW9RTW1sK2V1VnlUaENtcksrNDlHWStiR0ZvZGcrNGp0NDFvQ09GY0xiaGNONWpRREMrc29CVHlmb1RHODFpY3pzV1gwTnBzc2NSUzBOS0ZcL1loT3k4a01NcXhyZFlPMngxQ2hUNXFETzE3c3lISnZ6UFNtTHVFUDI3SEVSWDlTTWkxclN0QzZ3WTlOWFwvV3Ryb3h6R05HVXdYeFRcL2FDZEwzMTlwK3A3R1RyNmtoNzRicDlCN2xVUHMrTjZHdE9MV0FcL09tMW1DYWp0QVNLWG1uUnVCNzZrZzZxOWRKU3p4a1VidXFYSzN2OWpLSDkzOW5oTktxVnpRVDJmTFZDNGQ0MWpwRlMzSW5lN0U0cFwvU2tJbFV1SlJZXC9xWlFyU0NDaU5KN2I5a2hWbjhsMFA5b2FHSm40SjJWVTRBQXVtS3NjS290b1ArNTBqN0lvVUlZNUp6K0FFQnFYbStPbGoxakE3WjVld0NDNjN4V1RVMmU5aXAxMjlxVTgrOG0weWp4Z2xQYjBSTGMxRUZKSGFab0lFXC9pNk91SlpEUlBCeENcLzZ5WDg5UUZtZysxa0dMTFFzMGhmdDQzcStPOElyNklzT0gySlwvck9GcmJcL1NjcGxWSVR4ZXlMeDlwMzQyMGZKNDErbjNYVlRsbUxrc1pwTnV0UWhCeko4anVycjZsMmFBRWhlVXlYdld5aXhMRHNLc0hzb3IwUGxvTmRtekxMakRqNW9nbkpaNjZqN2toM3dvU1FXeHpIbzdvaWJFWXZ1SXJKNWQ0ODVFUWVUQlVoWmxvMXl0OHduWEJiMUh4UHJCZDh5eW5cL2h2K3lXbTRcL3ZUWVd2V0JjVzBOa2wwQkJMaENDZGpDbUVweEt1VnpOaGs4ZWFYdE51RGc0WVdlaEdCbm1kQm9yWlFBWlJDK3ZnaHJJNTJvT3JQXC9CNDVkN0hQSmxGSXhPN0g3Q3lSek9zQ1A4cWl3NWl1YWl5aU5kcXFvYk1lS29WOXY2dFgxRFNLNDNGaFY5N1FvQ1QxRzkxRUJxT04zWjc3dWdFYnBVWHBvcHFkTStuRCtBeXFrR09rd01yVkl0Rk1qYWdTYVRqNHBFNVNcL05sa0ZKRm1SRFp0UnF3ZnlJMUNNQ2IxSm5YOXpwREZiVTJ0Z2RGN295VWNTZXdOY3lsQ2VoaTJvMlhcL2UzS3l4b0k4ejlwQlZCYkxwbjJDQnRzbk5pXC9YUklZeVFBSFhqM2lrXC9oVkhRbnFpMzVvT1pPWXFlNHprOW9mdnhFdUVETlUxRXk0YUpxS0VaQUpLcE9Ma2JUMWU1Zz09IiwiZXhwIjo0MTAyNDQ4NDAwLCJjbGFpbV9rZXlfaWQiOiI3ODI0OTMzMTYiLCJpYXQiOjQxMDI0NDQ4MDAsImp0aSI6IjQ4YzJhMzI5LTVjM2ItNDYxNC05NzNjLTI0OTk5MWU1NjYwYSJ9.B_px5cFJPlzRBzS2Q4G2QPlzLBG7D1FlMGsUN21kNjkzdQ2lRpK66W_QWv3G_N5oPVaMVLfIrI_l_A7K6b_4EQHOWUZYQng4_QSnKIfBElUduiW4rv_NlxDo3aQc9ouoJuXanR6SzYJ9YOV7sUVqS76KwH9-sG_b6vNilSrrv1FD0W9np_8W6NBaPoMlBEsWgTR2ArGxTa8RxQWprjtNzoNPADNJBLjdPJqFPwENNKvooawO3O5WkJOLnQ-dr1MM37o9mEK-0bYkt3XhE_coSvnvRHYhKvz4GnUum7vAAQtZAJHGxNQj7SOSE8Wu3lqKn_jeaSLs-NwIIPE8ZgBuwA",
  "expires_in": 3600,
  "id_token": "eyJraWQiOiJrZXlfMjAyMV8wM18xOF8xMl80OF8zOV85ODEiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJtb2NrLXNwIiwic3ViIjoiY2I2ZTQwYjctMWUwNy00OGQwLWEzMmMtNGM5OTRkZjhhZmQ4IiwiYWNyIjoibG9hMSBsb2EyIGxvYTMiLCJuYmYiOjE2MTYwNjg0NTcsInNjb3BlIjoib3BlbmlkIiwiYXV0aF90aW1lIjoxNjE2MDY4MjA3LCJpc3MiOiJodHRwczpcL1wvb3JnLm9wZW5jb25leHQubG9jYWwub2lkYy5uZyIsImV4cCI6NDEwMjQ0ODQwMCwiaWF0Ijo0MTAyNDQ0ODAwLCJqdGkiOiJiNWEwNDdmYy0yMGI5LTRlYWItOWU2Ny04MDhjN2JlNmNiMmQifQ.UjK1inkkkb7gjBGu3jWr3HnP2lP1p28ARmpbyFvKVUuBMDQcJDvUYCOYL0OFoac7UDNdjoex32P740nXoTnnOV0DRy-Scuc94EVkeGeAak3R7Jh2I7xtE7vV1YAuWwfQAAFRx1-Fw6kbl9OfuOlxXl4dxa9QzSecbW5SwdbLpO8ySFHMzzKnQcPoD84p4fLHxAot_QLErudxn7TTaXkdXF9JLwjUmzRJkxEr5HyBQN1uYwvoK27czRqN2eBcU03lurJorvyfrPngQiBxlDY0-2RRNtihfLyxKEw1Ej6n8O2EBTngmppJXJz8xcyx8EY5tjNJKw39zUALWb1WONhnug"
}
```
### [cUrl OAuth2](#curl-oauth2-testing)
The OIDC protocol also support the OAuth2 flows like client_credentials:
```
curl -u playground_client:secret -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'grant_type=client_credentials' http://localhost:8080/oidc/token | jq .
```
And the subsequent output:
```json
{
  "access_token": "653c02ec-ad9e-4ae1-bb57-717ac907040c",
  "token_type": "Bearer",
  "refresh_token": "6e41e499-be8c-4be3-bc40-aa5279b0029a",
  "expires_in": 3600
}
```
Save the access_token in a variable:
```
export access_token=653c02ec-ad9e-4ae1-bb57-717ac907040c
```
And the call to the introspect endpoint:
```
curl -u resource-server-playground-client:secret -H "Content-Type: application/x-www-form-urlencoded" -X POST "http://localhost:8080/oidc/introspect?token=${access_token}" | jq .
```
And the output - note that there is no user-info, because no authentication has taken place because of the nature of client_credentials:
```json
{
  "active": true,
  "client_id": "playground_client",
  "exp": 1580917538,
  "iss": "https://org.openconext.oidc.ng",
  "scope": "openid,groups",
  "sub": "playground_client",
  "token_type": "Bearer"
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
The OpenID Connect Provider has administrator endpoints to rollover both the signing keys as the symmetric keys. The signing keys are used to
sign and verify the JWT tokens. The symmetric keys are used to encrypt and decrypt the user claims in the access_token.

To rollover the signing key and clean up unreferenced signing keys:
```
curl -u manage:secret "http://localhost:8080/manage/force-signing-key-rollover"
```
To rollover the symmetric key and clean up unreferenced symmetric keys:
```
curl -u manage:secret "http://localhost:8080/manage/force-symmetric-key-rollover"
```
## [SAML metadata](#saml-metadata)

The metadata is generated on the fly and is displayed on http://localhost:8080/saml/metadata

## [Trusted Proxy](#trusted-proxy)

OpenConext-OIDC is a proxy for SP's that want to use OpenConnect ID instead of SAML to provide their Service to the federation members.
Therefore the WAYF and ARP must be scoped for the requesting SP (and not this OIDC SP). This works if the OIDC-proxy is configured with the `coin:trusted_proxy` and `redirect.sign` settings in Manage.

## [Consent](#consent)

Running OIDC-NG on localhost you can test the consent page by visiting
[the consent page](http://localhost:8080/oidc/authorize?scope=openid&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fredirect&state=example&prompt=consent&nonce=example&client_id=playground_client&response_mode=query)

## [Token-API](#topenapi)
If you run the `TokenControllerTest` the test seed resides in the mongo test database. Fetch all tokens
```
curl -u eduid:secret "http://localhost:8080/tokens?unspecifiedID=urn%3Acollab%3Aperson%3Aeduid.nl%3A7d4fca9b-2169-4d55-8347-73cf29b955a2"
```
The result:
```
[
  {
    "expiresIn": "2020-03-21T07:23:19.096+0000",
    "createdAt": "2020-06-19T07:23:19.096+0000",
    "id": "5eec6a5df0efad206831a65a",
    "clientName": "Playground Client",
    "audiences": [
      "ResourceServer",
      "OpenConext Mock SP"
    ],
    "scopes": [
      {
        "name": "openid",
        "descriptions": {
          "en": "See all your account information.",
          "nl": "nl",
          "pt": "pt"
        }
      },
      {
        "name": "groups",
        "descriptions": {
          "en": "Have access to all your group memberships.",
          "nl": "nl",
          "pt": "pt"
        }
      },
      {
        "name": "nope",
        "descriptions": {}
      }
    ],
    "type": "ACCESS"
  },
  {
    "expiresIn": "2020-03-21T07:23:19.105+0000",
    "createdAt": "2020-06-19T07:23:19.105+0000",
    "id": "5eec6a5df0efad206831a658",
    "clientName": "OpenConext Mock RP",
    "audiences": [],
    "scopes": [
      {
        "name": "openid",
        "descriptions": {
          "en": "English description",
          "nl": "nl",
          "pt": "pt"
        }
      },
      {
        "name": "groups",
        "descriptions": {}
      },
      {
        "name": "nope",
        "descriptions": {}
      }
    ],
    "type": "REFRESH"
  }
]
```
To delete tokens perform the following:
```
curl -u eduid:secret -H "Content-type: application/json" -X PUT -d '[{"id":"5eec6a5df0efad206831a658","tokenType":"REFRESH"},{"id":"5eec6a5df0efad206831a659","tokenType":"ACCESS"}]' 'http://localhost:8080/tokens'
```
## [JMeter performance](#performance)
In `src\jmeter` there is a JMeter project file to perform load / stress tests.
```
cd src/jmeter
jmeter -n -t OIDC-NG.jmx -l results.log
```
