package oidc.saml;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import oidc.SeedUtils;
import oidc.model.AuthenticationRequest;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.UserRepository;
import oidc.user.OidcSamlAuthentication;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.ResponseUnmarshaller;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

public class ResponseAuthenticationConverterTest extends AbstractSamlUnitTest implements SeedUtils {

    private UserRepository userRepository = mock(UserRepository.class);
    private AuthenticationRequestRepository authenticationRequestRepository = mock(AuthenticationRequestRepository.class);

    private ResponseAuthenticationConverter subject = new ResponseAuthenticationConverter(
            userRepository, authenticationRequestRepository, new ObjectMapper(), new ClassPathResource("oidc/saml_mapping.json")
    );

    public ResponseAuthenticationConverterTest() throws IOException {
    }

    @Before
    public void before() {
        reset(userRepository, authenticationRequestRepository);
    }

    @Test
    public void login() throws XMLParserException, UnmarshallingException, IOException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        when(authenticationRequestRepository.findById(anyString())).thenReturn(Optional.of(
                new AuthenticationRequest("id", new Date(), "clientId", "http://some")));

        OidcSamlAuthentication oidcSamlAuthentication = doLogin("saml/authn_response.xml");
        String sub = oidcSamlAuthentication.getUser().getSub();
        assertEquals("270E4CB4-1C2A-4A96-9AD3-F28C39AD1110", sub);
    }

    @Test
    public void loginExistingUser() throws XMLParserException, UnmarshallingException, IOException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        when(authenticationRequestRepository.findById(anyString())).thenReturn(Optional.of(
                new AuthenticationRequest("id", new Date(), "clientId", "http://some")));
        when(userRepository.findOptionalUserBySub(anyString())).thenReturn(Optional.of(user("key")));

        doLogin("saml/authn_response.xml");
    }

    @Test
    public void loginWithNoAuthnContext() throws XMLParserException, UnmarshallingException, IOException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        when(authenticationRequestRepository.findById(anyString())).thenReturn(Optional.of(
                new AuthenticationRequest("id", new Date(), "clientId", "http://some")));

        OidcSamlAuthentication oidcSamlAuthentication = doLogin("saml/no_authn_context_response.xml");
        List<String> acrClaims = oidcSamlAuthentication.getUser().getAcrClaims();

        assertEquals(1,acrClaims.size());
        assertEquals("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified", acrClaims.get(0));
    }

    private OidcSamlAuthentication doLogin(String path) throws IOException, UnmarshallingException, XMLParserException, ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        InputStream inputStream = new ClassPathResource(path).getInputStream();
        String saml2Response = IOUtils.toString(inputStream, Charset.defaultCharset());
        Response response = unmarshall(saml2Response);

        Saml2AuthenticationToken token = new Saml2AuthenticationToken(relyingParty, saml2Response);

        OpenSamlAuthenticationProvider.ResponseToken responseToken = getResponseToken(response, token);

        OidcSamlAuthentication authentication = subject.convert(responseToken);

        assertEquals("urn:collab:person:example.com:admin", authentication.getName());
        return authentication;
    }

    //See https://github.com/spring-projects/spring-security/issues/9004
    private OpenSamlAuthenticationProvider.ResponseToken getResponseToken(Response response, Saml2AuthenticationToken token) throws ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Class<?> c = Class.forName("org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider$ResponseToken");
        Constructor<?> declaredConstructor = c.getDeclaredConstructor(Response.class, Saml2AuthenticationToken.class);

        declaredConstructor.setAccessible(true);
        OpenSamlAuthenticationProvider.ResponseToken responseToken = (OpenSamlAuthenticationProvider.ResponseToken) declaredConstructor.newInstance(response, token);
        return responseToken;
    }

    private Response unmarshall(String saml2Response) throws UnmarshallingException, XMLParserException {
        XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
        ResponseUnmarshaller responseUnmarshaller = (ResponseUnmarshaller) registry.getUnmarshallerFactory()
                .getUnmarshaller(Response.DEFAULT_ELEMENT_NAME);
        ParserPool parserPool = registry.getParserPool();
        Document doc = parserPool.parse(new ByteArrayInputStream(saml2Response.getBytes()));
        Element samlElement = doc.getDocumentElement();

        return (Response) responseUnmarshaller.unmarshall(samlElement);
    }
}