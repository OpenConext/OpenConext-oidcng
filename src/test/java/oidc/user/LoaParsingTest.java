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

public class LoaParsingTest implements SamlTest {

    @Test
    public void parseRequestedAuthnContext() throws IOException {
        AuthenticationRequest authenticationRequest = resolveFromXMLFile(AuthenticationRequest.class, "saml/loa_authn_request.xml");
        RequestedAuthenticationContext requestedAuthenticationContext = authenticationRequest.getRequestedAuthenticationContext();
        //TODO ensure the values http://surfconext.nl/assurance/loa2 are present.
        // Wait for pull request https://github.com/spring-projects/spring-security-saml/pull/440 to be accepted.
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
        String classReference = authenticationStatement.getAuthenticationContext().getClassReference().toString();
        //TODO ensure the classReference is http://stepup.example.org/verified-second-factor/level2
        // Wait for pull request https://github.com/spring-projects/spring-security-saml/pull/440 to be accepted.
    }


}
