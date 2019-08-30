package oidc.user;

import oidc.model.User;
import oidc.repository.UserRepository;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

//Hard to test, because of SAML dependency
public class SamlProvisioningAuthenticationManagerTest implements SamlTest {

    private UserRepository userRepository = mock(UserRepository.class);
    private SamlProvisioningAuthenticationManager subject = new SamlProvisioningAuthenticationManager(userRepository, objectMapper);

    public SamlProvisioningAuthenticationManagerTest() throws IOException {
    }

    @Test
    public void authenticate() throws IOException {
        Response response = resolveFromXMLFile(Response.class, "saml/authn_response.xml");
        String inResponseTo = response.getInResponseTo();

        Assertion assertion = response.getAssertions().get(0);
        DefaultSamlAuthentication samlAuthentication = new DefaultSamlAuthentication(true, assertion, null, null, "oidc_client");
        samlAuthentication.setResponseXml(IOUtils.toString(new ClassPathResource("saml/authn_response.xml").getInputStream(), Charset.defaultCharset()));
        OidcSamlAuthentication authenticate = (OidcSamlAuthentication) subject.authenticate(samlAuthentication);

        assertEquals(User.class, authenticate.getDetails().getClass());
        assertNull(authenticate.getCredentials());
        assertEquals(0, authenticate.getAuthorities().size());
        assertTrue(authenticate.isAuthenticated());

        User user = authenticate.getUser();
        String sub = user.getSub();

        assertEquals("oidc_client", user.getClientId());
        assertEquals("270E4CB4-1C2A-4A96-9AD3-F28C39AD1110", user.getSub());
        assertEquals("urn:collab:person:example.com:admin", user.getUnspecifiedNameId());
        assertEquals("http://mock-idp", user.getAuthenticatingAuthority());
        assertEquals(Collections.singletonList("http://test.surfconext.nl/assurance/loa2"), user.getAcrClaims());
        assertEquals("j.doe@example.com", user.getAttributes().get("email"));
        assertEquals(Collections.singleton("admin"), user.getAttributes().get("uids"));


        when(userRepository.findOptionalUserBySub(user.getSub())).thenReturn(Optional.of(user));
        when(userRepository.insert(any(User.class))).thenThrow(IllegalArgumentException.class);
        when(userRepository.save(any(User.class))).thenThrow(IllegalArgumentException.class);

        authenticate = (OidcSamlAuthentication) subject.authenticate(samlAuthentication);
        user = authenticate.getUser();
        assertEquals(sub, user.getSub());

        assertion.getFirstAttribute("urn:mace:dir:attribute-def:mail").setValues(Collections.singletonList("changed@example.org"));
        when(userRepository.save(any(User.class))).thenReturn(user);

        authenticate = (OidcSamlAuthentication) subject.authenticate(samlAuthentication);
        user = authenticate.getUser();

        assertEquals("changed@example.org", user.getAttributes().get("email"));

        assertion.setAttributes(assertion.getAttributes().stream().filter(attr -> !attr.getName().equals("urn:mace:dir:attribute-def:eduPersonTargetedID"))
                .collect(Collectors.toList()));

        when(userRepository.insert(any(User.class))).thenReturn(user);
        authenticate = (OidcSamlAuthentication) subject.authenticate(samlAuthentication);
        user = authenticate.getUser();

        assertNotEquals(sub, user.getSub());
        assertEquals(true, uuidPattern.matcher(user.getSub()).matches());
    }

}