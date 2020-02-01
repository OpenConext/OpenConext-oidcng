package oidc.secure;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import oidc.exceptions.UnsupportedJWTException;
import oidc.model.OpenIDClient;
import org.apache.commons.io.IOUtils;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import static java.nio.charset.Charset.defaultCharset;

public class JWTRequest {

    public static AuthenticationRequest parse(AuthenticationRequest authenticationRequest, OpenIDClient openIDClient)
            throws CertificateException, JOSEException, IOException, BadJOSEException, ParseException, com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {
        if (!openIDClient.certificateSpecified()) {
            throw new UnsupportedJWTException(String.format("RP %s does not have a certificate, url or discovery url. ", openIDClient.getClientId()));
        }
        JWT jwt = authenticationRequest.getRequestObject();
        if (jwt == null) {
            String requestURL = authenticationRequest.getRequestURI().toString();
            jwt = SignedJWT.parse(read(requestURL));
        }
        if (!(jwt instanceof SignedJWT)) {
            throw new UnsupportedJWTException("JWT is not a SignedJWT, but " + jwt.getClass().getName());
        }
        SignedJWT signedJWT = (SignedJWT) jwt;
        String signingCertificate;
        if (StringUtils.hasText(openIDClient.getSigningCertificateUrl())) {
            signingCertificate = read(openIDClient.getSigningCertificateUrl());
        } else if (StringUtils.hasText(openIDClient.getSigningCertificate())) {
            signingCertificate = openIDClient.getSigningCertificate();
        } else {
            String discovery = read(openIDClient.getDiscoveryUrl());
            String jwksUri = (String) JSONObjectUtils.parse(discovery).get("jwks_uri");
            signingCertificate = read(jwksUri);
        }
        JWTClaimsSet claimsSet = claimsSet(jwkSet(signingCertificate), signedJWT);

        return mergeAuthenticationRequest(authenticationRequest, claimsSet.getClaims());
    }

    private static String read(String url) throws IOException {
        return IOUtils.toString(new URL(url).openStream(), defaultCharset());
    }

    private static JWKSet jwkSet(String signingCertificate) throws CertificateException, JOSEException, ParseException {
        if (signingCertificate.trim().startsWith("{") && signingCertificate.contains("keys")) {
            return JWKSet.parse(signingCertificate);
        }
        if (!signingCertificate.contains("BEGIN CERTIFICATE")) {
            signingCertificate = "-----BEGIN CERTIFICATE-----\n" + signingCertificate + "\n-----END CERTIFICATE-----";
        }
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(signingCertificate.getBytes()));
        return new JWKSet(RSAKey.parse(cert));
    }

    @SuppressWarnings("unchecked")
    private static JWTClaimsSet claimsSet(JWKSet jwkSet, SignedJWT signedJWT) throws BadJOSEException, JOSEException {
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWSKeySelector keySelector = new JWSVerificationKeySelector(signedJWT.getHeader().getAlgorithm(), new ImmutableJWKSet(jwkSet));
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor.process(signedJWT, null);
    }

    private static AuthenticationRequest mergeAuthenticationRequest(AuthenticationRequest authenticationRequest, Map<String, Object> claims) throws com.nimbusds.oauth2.sdk.ParseException, URISyntaxException {
        return new AuthenticationRequest(
                authenticationRequest.getEndpointURI(),
                claims.containsKey("response_type") ? ResponseType.parse((String) claims.get("response_type")) : authenticationRequest.getResponseType(),
                claims.containsKey("response_mode") ? new ResponseMode((String) claims.get("response_mode")) : authenticationRequest.getResponseMode(),
                claims.containsKey("scope") ? Scope.parse((String) claims.get("scope")) : authenticationRequest.getScope(),
                claims.containsKey("client_id") ? new ClientID((String) claims.get("client_id")) : authenticationRequest.getClientID(),
                claims.containsKey("redirect_uri") ? new URI((String) claims.get("redirect_uri")) : authenticationRequest.getRedirectionURI(),
                claims.containsKey("state") ? new State((String) claims.get("state")) : authenticationRequest.getState(),
                claims.containsKey("nonce") ? new Nonce((String) claims.get("nonce")) : authenticationRequest.getNonce(),
                claims.containsKey("display") ? Display.parse((String) claims.get("display")) : authenticationRequest.getDisplay(),
                claims.containsKey("prompt") ? Prompt.parse((String) claims.get("prompt")) : authenticationRequest.getPrompt(),
                claims.containsKey("maxAge") ? (Integer) claims.get("max_age") : authenticationRequest.getMaxAge(),
                authenticationRequest.getUILocales(),
                authenticationRequest.getClaimsLocales(),
                authenticationRequest.getIDTokenHint(),
                claims.containsKey("login_hint") ? (String) claims.get("login_hint") : authenticationRequest.getLoginHint(),
                claims.containsKey("acr_values") ? Arrays.asList(((String) claims.get("acr_values")).split(" ")).stream().map(ACR::new).collect(Collectors.toList()) : authenticationRequest.getACRValues(),
                claims.containsKey("claims") ? ClaimsRequest.parse((String) claims.get("claims")) : authenticationRequest.getClaims(),
                authenticationRequest.getPurpose(),
                authenticationRequest.getRequestObject(),
                authenticationRequest.getRequestURI(),
                claims.containsKey("code_challenge") ? CodeChallenge.parse((String) claims.get("code_challenge")) : authenticationRequest.getCodeChallenge(),
                claims.containsKey("code_challenge_method") ? CodeChallengeMethod.parse((String) claims.get("code_challenge_method")) : authenticationRequest.getCodeChallengeMethod(),
                authenticationRequest.getResources(),
                authenticationRequest.includeGrantedScopes(),
                authenticationRequest.getCustomParameters());
    }

}
