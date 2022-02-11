package oidc.saml;

import lombok.SneakyThrows;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import oidc.crypto.KeyGenerator;
import org.apache.commons.io.IOUtils;
import org.junit.BeforeClass;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.ResponseUnmarshaller;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public abstract class AbstractSamlUnitTest {

    protected static Saml2X509Credential saml2X509Credential;
    protected static PortResolver portResolver = new PortResolverImpl();
    protected static RelyingPartyRegistration relyingParty;

    @BeforeAll
    @BeforeClass
    public static void beforeClass() {
        saml2X509Credential = getSigningCredential();
        OpenSamlInitializationService.initialize();

        relyingParty = RelyingPartyRegistration
                .withRegistrationId("oidcng")
                .entityId("entityID")
                .signingX509Credentials(c -> c.add(saml2X509Credential))
                .assertionConsumerServiceLocation("https://acs")
                .assertingPartyDetails(builder -> builder
                        .entityId("entityID")
                        .wantAuthnRequestsSigned(false)
                        .singleSignOnServiceLocation("https://sso").build())
                .build();
    }

    @SneakyThrows
    private static Saml2X509Credential getSigningCredential() {
        String[] keys = KeyGenerator.generateKeys();
        String pem = keys[0];
        String certificate = keys[1];
        PrivateKey privateKey = KeyGenerator.readPrivateKey(pem);
        byte[] certBytes = KeyGenerator.getDER(certificate);
        X509Certificate x509Certificate = KeyGenerator.getCertificate(certBytes);

        return new Saml2X509Credential(privateKey, x509Certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
    }

    //See https://github.com/spring-projects/spring-security/issues/9004
    public OpenSaml4AuthenticationProvider.ResponseToken getResponseToken(Response response, Saml2AuthenticationToken token) throws ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Class<?> c = Class.forName("org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider$ResponseToken");
        Constructor<?> declaredConstructor = c.getDeclaredConstructor(Response.class, Saml2AuthenticationToken.class);

        declaredConstructor.setAccessible(true);
        OpenSaml4AuthenticationProvider.ResponseToken responseToken = (OpenSaml4AuthenticationProvider.ResponseToken) declaredConstructor.newInstance(response, token);
        return responseToken;
    }

    public Response unmarshall(String saml2Response) throws UnmarshallingException, XMLParserException {
        XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
        ResponseUnmarshaller responseUnmarshaller = (ResponseUnmarshaller) registry.getUnmarshallerFactory()
                .getUnmarshaller(Response.DEFAULT_ELEMENT_NAME);
        ParserPool parserPool = registry.getParserPool();
        Document doc = parserPool.parse(new ByteArrayInputStream(saml2Response.getBytes()));
        Element samlElement = doc.getDocumentElement();

        return (Response) responseUnmarshaller.unmarshall(samlElement);
    }

    public OpenSaml4AuthenticationProvider.ResponseToken getResponseToken(String path) throws IOException, UnmarshallingException, XMLParserException, ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        InputStream inputStream = new ClassPathResource(path).getInputStream();
        String saml2Response = IOUtils.toString(inputStream, Charset.defaultCharset());
        Response response = unmarshall(saml2Response);

        Saml2AuthenticationToken token = new Saml2AuthenticationToken(relyingParty, saml2Response);

        return getResponseToken(response, token);
    }





}
