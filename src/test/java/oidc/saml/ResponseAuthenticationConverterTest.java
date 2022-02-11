package oidc.saml;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import oidc.SeedUtils;
import oidc.model.AuthenticationRequest;
import oidc.model.User;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.UserRepository;
import oidc.user.OidcSamlAuthentication;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

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
        User user = oidcSamlAuthentication.getUser();
        String sub = user.getSub();
        assertEquals("270E4CB4-1C2A-4A96-9AD3-F28C39AD1110", sub);
        assertEquals("urn:collab:person:example.com:admin", oidcSamlAuthentication.getName());
        assertEquals(3, ((List) user.getAttributes().get("eduperson_affiliation")).size());
    }

    @Test
    public void loginExistingUser() throws XMLParserException, UnmarshallingException, IOException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        when(authenticationRequestRepository.findById(anyString())).thenReturn(Optional.of(
                new AuthenticationRequest("id", new Date(), "clientId", "http://some")));
        when(userRepository.findOptionalUserBySub(anyString())).thenReturn(Optional.of(user("key")));

        OidcSamlAuthentication oidcSamlAuthentication = doLogin("saml/authn_response.xml");
        assertEquals("urn:collab:person:example.com:admin", oidcSamlAuthentication.getName());
    }

    @Test
    public void loginExistingUserWithCollab() throws XMLParserException, UnmarshallingException, IOException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        when(authenticationRequestRepository.findById(anyString())).thenReturn(Optional.of(
                new AuthenticationRequest("id", new Date(), "clientId", "http://some")));
        when(userRepository.findOptionalUserBySub(anyString())).thenReturn(Optional.of(user("key")));

        OidcSamlAuthentication oidcSamlAuthentication = doLogin("saml/authn_response_collab_person.xml");

        String unspecifiedNameId = oidcSamlAuthentication.getUser().getUnspecifiedNameId();
        assertEquals("internal-collabPersonId", unspecifiedNameId);

        String sub = oidcSamlAuthentication.getUser().getSub();
        assertEquals("persistent", sub);
    }

    @Test
    public void loginWithNoAuthnContext() throws XMLParserException, UnmarshallingException, IOException, ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        when(authenticationRequestRepository.findById(anyString())).thenReturn(Optional.of(
                new AuthenticationRequest("id", new Date(), "clientId", "http://some")));

        OidcSamlAuthentication oidcSamlAuthentication = doLogin("saml/no_authn_context_response.xml");
        assertEquals("urn:collab:person:example.com:admin", oidcSamlAuthentication.getName());

        List<String> acrClaims = oidcSamlAuthentication.getUser().getAcrClaims();
        assertEquals(1, acrClaims.size());
        assertEquals("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified", acrClaims.get(0));
    }

    private OidcSamlAuthentication doLogin(String path) throws IOException, UnmarshallingException, XMLParserException, ClassNotFoundException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        OpenSaml4AuthenticationProvider.ResponseToken responseToken = getResponseToken(path);
        return subject.convert(responseToken);
    }

}