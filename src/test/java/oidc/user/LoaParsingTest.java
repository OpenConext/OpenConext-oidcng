package oidc.user;

import org.junit.Test;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.AuthenticationStatement;
import org.springframework.security.saml.saml2.authentication.RequestedAuthenticationContext;
import org.springframework.security.saml.saml2.authentication.Response;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

public class LoaParsingTest extends AbstractSamlTest {

    @Test
    public void parseRequestedAuthnContext() throws IOException {
        AuthenticationRequest authenticationRequest = resolveXml(AuthenticationRequest.class, "saml/loa_authn_request.xml");
        RequestedAuthenticationContext requestedAuthenticationContext = authenticationRequest.getRequestedAuthenticationContext();
        //TODO ensure the values http://surfconext.nl/assurance/loa2 are present. Wait for pull request to be accepted.
    }

    @Test
    public void parseAuthnContextClassRef() throws IOException {
        Response response = resolveXml(Response.class, "saml/loa_authn_response.xml");
        List<AuthenticationStatement> authenticationStatements = response.getAssertions()
                .stream()
                .map(Assertion::getAuthenticationStatements)
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
        assertEquals(1, authenticationStatements.size());

        AuthenticationStatement authenticationStatement = authenticationStatements.get(0);
        authenticationStatement.getAuthenticationContext().getClassReference().toString();


    }


}
