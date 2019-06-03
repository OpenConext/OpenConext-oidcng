package oidc.secure;

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
import java.util.Base64;

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

}
