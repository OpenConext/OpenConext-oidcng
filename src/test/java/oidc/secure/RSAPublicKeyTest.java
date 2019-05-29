package oidc.secure;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class RSAPublicKeyTest {

    @Test
    public void rsaKeyFromPem() throws IOException, CertificateException, JOSEException {
        String cert = IOUtils.toString(new ClassPathResource("oidc/demo.pem").getInputStream(), Charset.defaultCharset());
        cert = "-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END CERTIFICATE-----";
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(cert.getBytes()));
        RSAKey rsaKey = RSAKey.parse(certificate);
        System.out.println(rsaKey);

        cert = IOUtils.toString(new ClassPathResource("oidc/demo.crt").getInputStream(), Charset.defaultCharset());
        certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(cert.getBytes()));
        rsaKey = RSAKey.parse(certificate);
        System.out.println(rsaKey);
    }
}
