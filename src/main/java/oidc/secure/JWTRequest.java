package oidc.secure;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import oidc.exceptions.UnsupportedJWTException;
import oidc.model.OpenIDClient;
import org.apache.commons.io.IOUtils;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.nio.charset.Charset.defaultCharset;

public class JWTRequest {

    public static Map<String, String> parse(AuthenticationRequest authenticationRequest, OpenIDClient openIDClient)
            throws CertificateException, JOSEException, IOException, ParseException, BadJOSEException {
        if (!openIDClient.certificateSpecified()) {
            throw new UnsupportedJWTException(String.format("RP %s does not have a certificate, url or discovery url. ",openIDClient.getClientId()));
        }
        Map<String, List<String>> parameters = authenticationRequest.toParameters();

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
        if (StringUtils.hasText(openIDClient.getSigningCertificate())) {
            signingCertificate = openIDClient.getSigningCertificate();
        } else if (StringUtils.hasText(openIDClient.getSigningCertificateUrl())) {
            signingCertificate = read(openIDClient.getSigningCertificateUrl());
        } else {
            String discovery = read(openIDClient.getDiscoveryUrl());
            String jwksUri = (String) JSONObjectUtils.parse(discovery).get("jwks_uri");
            signingCertificate = read(jwksUri);
        }
        JWTClaimsSet claimsSet = claimsSet(jwkSet(signingCertificate), signedJWT);

        Map<String, String> result = new HashMap<>();
        parameters.forEach((key, val) -> result.put(key, val.get(0)));
        claimsSet.getClaims().forEach((key, val) -> result.put(key, val.toString()));

        return result;
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

}
