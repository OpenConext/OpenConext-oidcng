package oidc.user;

import org.junit.Test;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.AuthenticationStatement;
import org.springframework.security.saml.saml2.authentication.RequestedAuthenticationContext;
import org.springframework.security.saml.saml2.authentication.Response;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

public class LoaParsingTest implements SamlTest {

    @Test
    public void parseRequestedAuthnContext() throws IOException {
        AuthenticationRequest authenticationRequest = resolveFromXMLFile(AuthenticationRequest.class, "saml/loa_authn_request.xml");
        RequestedAuthenticationContext requestedAuthenticationContext = authenticationRequest.getRequestedAuthenticationContext();
        List<String> loas = authenticationRequest.getAuthenticationContextClassReferences().stream().map(ref -> ref.getValue()).collect(Collectors.toList());
        assertEquals(Arrays.asList("http://surfconext.nl/assurance/loa1", "http://surfconext.nl/assurance/loa2"), loas);
    }

    @Test
    public void parseAuthnContextClassRef() throws IOException {
        Response response = resolveFromXMLFile(Response.class, "saml/loa_authn_response.xml");
        List<AuthenticationStatement> authenticationStatements = response.getAssertions()
                .stream()
                .map(Assertion::getAuthenticationStatements)
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
        assertEquals(1, authenticationStatements.size());

        AuthenticationStatement authenticationStatement = authenticationStatements.get(0);
        String loa = authenticationStatement.getAuthenticationContext().getClassReference().getValue();
        assertEquals("http://stepup.example.org/verified-second-factor/level2", loa);
    }


}
