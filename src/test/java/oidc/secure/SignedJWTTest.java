package oidc.secure;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import oidc.model.OpenIDClient;
import org.apache.commons.io.IOUtils;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public interface SignedJWTTest {

    default void setCertificateFields(OpenIDClient client, String signingCertificate, String signingCertificateUrl, String discoveryUrl) {
        ReflectionTestUtils.setField(client, "signingCertificate", signingCertificate);
        ReflectionTestUtils.setField(client, "signingCertificateUrl", signingCertificateUrl);
        ReflectionTestUtils.setField(client, "discoveryUrl", discoveryUrl);
    }

    default String getCertificateKeyID(OpenIDClient client) throws CertificateException {
        String cert = "-----BEGIN CERTIFICATE-----\n" + client.getSigningCertificate() + "\n-----END CERTIFICATE-----";
        return getCertificateKeyIDFromCertificate(cert);
    }

    default String getCertificateKeyIDFromCertificate(String cert) throws CertificateException {
        return ((X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(cert.getBytes())))
                .getSerialNumber().toString(10);
    }

    default RSAPrivateKey privateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String privateKey = IOUtils.toString(new ClassPathResource("keys/key.pem").getInputStream(), Charset.defaultCharset())
                .replaceAll("\\Q-----BEGIN PRIVATE KEY-----\\E|\\Q-----END PRIVATE KEY-----\\E|\n", "");
        byte[] decodedKey = Base64.getDecoder().decode(privateKey.getBytes());
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }

    default SignedJWT signedJWT(String clientId, String keyID, String redirectURI) throws Exception {
        ClaimsRequest claimsRequest = new ClaimsRequest();
        claimsRequest.addIDTokenClaim("email");

        Instant instant = Clock.systemDefaultZone().instant();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .audience("audience")
                .expirationTime(Date.from(instant.plus(3600, ChronoUnit.SECONDS)))
                .jwtID(UUID.randomUUID().toString())
                .issuer(clientId)
                .issueTime(Date.from(instant))
                .subject(clientId)
                .notBeforeTime(new Date(System.currentTimeMillis()))
                .claim("redirect_uri", redirectURI)
                .claim("scope", "openid groups")
                .claim("nonce", "123456")
                .claim("state", "new")
                .claim("prompt", "login")
                .claim("claims", claimsRequest.toString())
                .claim("acr_values", "loa1 loa2 loa3");
        JWTClaimsSet claimsSet = builder.build();
        JWSHeader header = new JWSHeader.Builder(TokenGenerator.signingAlg).type(JOSEObjectType.JWT).keyID(keyID).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        JWSSigner jswsSigner = new RSASSASigner(privateKey());
        signedJWT.sign(jswsSigner);
        return signedJWT;
    }


}
