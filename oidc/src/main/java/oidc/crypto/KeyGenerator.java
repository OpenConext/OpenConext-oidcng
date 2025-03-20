package oidc.crypto;

import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.CharArrayReader;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;

public class KeyGenerator {

    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----\n";
    private static final String END_CERT = "-----END CERTIFICATE-----";
    private static final String BEGIN_KEY = "-----BEGIN RSA PRIVATE KEY-----\n";
    private static final String END_KEY = "-----END RSA PRIVATE KEY-----";

    private static final BouncyCastleProvider bcProvider = new BouncyCastleProvider();

    static {
        Security.addProvider(bcProvider);
    }

    private KeyGenerator() {
    }

    public static String[] generateKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        //PrivateKey is PKCS8 format and we need to end up in PEM format
        Writer writer = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(kp.getPrivate());
        pemWriter.close();

        String pemString = writer.toString();
        String certificate = certificate(kp);

        return new String[]{pemString, certificate};
    }


    public static String certificate(KeyPair keyPair) throws OperatorCreationException, CertificateException, CertIOException {
        X500Name dnName = new X500Name("CN=test,O=Test Certificate");
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());

        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        dnName,
                        new BigInteger(Long.toString(System.currentTimeMillis())),
                        new Date(),
                        Date.from(LocalDateTime.now().plusYears(1).toInstant(ZoneOffset.UTC)),
                        dnName,
                        keyPair.getPublic());

        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(bcProvider)
                .getCertificate(certBuilder.build(contentSigner));

        String result = "-----BEGIN CERTIFICATE-----\n";
        result += Base64.getEncoder().encodeToString(certificate.getEncoded());
        result += "\n-----END CERTIFICATE-----\n";
        return result;
    }

    @SneakyThrows
    public static String oneWayHash(String original, String secret) {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
        messageDigest.update(secret.getBytes());
        return new String(Hex.encode(messageDigest.digest(original.getBytes())));
    }


    public static byte[] getDER(String pem) {
        String data = keyCleanup(pem);
        return Base64.getDecoder().decode(data);
    }

    public static String keyCleanup(String pem) {
        return pem
                .replace(BEGIN_CERT, "")
                .replace(END_CERT, "")
                .replace(BEGIN_KEY, "")
                .replace(END_KEY, "")
                .replaceAll("[\n\t\n]", "")
                .trim();
    }

    @SneakyThrows
    public static X509Certificate getCertificate(byte[] der) {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
    }

    @SneakyThrows
    public static PrivateKey readPrivateKey(String pem) {

        PEMParser parser = new PEMParser(new CharArrayReader(pem.toCharArray()));
        Object obj = parser.readObject();
        parser.close();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair kp;
        if (obj instanceof PEMEncryptedKeyPair) {
            // Encrypted key - we will use provided password
            PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) obj;
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build("".toCharArray());
            kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
        } else {
            // Unencrypted key - no password needed
            PEMKeyPair ukp = (PEMKeyPair) obj;
            kp = converter.getKeyPair(ukp);
        }

        return kp.getPrivate();
    }

}
