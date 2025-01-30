package oidc.saml;

import oidc.model.SamlAuthenticationRequest;
import oidc.repository.SamlAuthenticationRequestRepository;
import org.apache.commons.codec.CodecPolicy;
import org.apache.commons.codec.binary.Base64;
import org.apache.groovy.util.ObjectHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.*;

class MongoSaml2AuthenticationRequestRepositoryTest extends AbstractSamlUnitTest {

    private final SamlAuthenticationRequestRepository samlAuthenticationRequestRepository = mock(SamlAuthenticationRequestRepository.class);
    private static final Base64 BASE64 = new Base64(0, new byte[]{'\n'}, false, CodecPolicy.STRICT);
    private final MongoSaml2AuthenticationRequestRepository subject = new MongoSaml2AuthenticationRequestRepository(samlAuthenticationRequestRepository, relyingParty);

    @BeforeEach
    public void before() {
        reset(samlAuthenticationRequestRepository);
    }

    @Test
    void authenticationRequestFlow() {
        String authnRequest = readFile("saml/authn_request.xml");
        String samlRequest = BASE64.encodeAsString(authnRequest.getBytes(StandardCharsets.UTF_8));
        Saml2RedirectAuthenticationRequest authenticationRequest = Saml2RedirectAuthenticationRequest
                .withRelyingPartyRegistration(relyingParty)
                .signature("signature")
                .sigAlg("sigAlg")
                .relayState("relaySate")
                .samlRequest(samlRequest)
                .build();
        MockHttpServletRequest request = new MockHttpServletRequest();

        String authnResponse = readFile("saml/authn_response.xml");
        String samlResponse = BASE64.encodeAsString(authnResponse.getBytes(StandardCharsets.UTF_8));

        request.setParameter(Saml2ParameterNames.SAML_RESPONSE, samlResponse);
        ObjectHolder<SamlAuthenticationRequest> argumentObjectHolder = new ObjectHolder<>();
        when(samlAuthenticationRequestRepository.save(any())).thenAnswer(i -> {
            SamlAuthenticationRequest argument = i.getArgument(0);
            argumentObjectHolder.setObject(argument);
            return argument;
        });
        subject.saveAuthenticationRequest(authenticationRequest, request, null);

        when(samlAuthenticationRequestRepository.findById(anyString())).thenReturn(Optional.of(argumentObjectHolder.getObject()));
        Saml2RedirectAuthenticationRequest result = (Saml2RedirectAuthenticationRequest) subject.loadAuthenticationRequest(request);
        assertEquals("https://sso", result.getAuthenticationRequestUri());

        result = (Saml2RedirectAuthenticationRequest) subject.removeAuthenticationRequest(request, null);
        assertEquals("https://sso", result.getAuthenticationRequestUri());
    }

    @Test
    void nonHappyFlow() {
        HttpServletRequest request = new MockHttpServletRequest();
        AbstractSaml2AuthenticationRequest authenticationRequest = subject.loadAuthenticationRequest(request);
        assertNull(authenticationRequest);

        authenticationRequest = subject.removeAuthenticationRequest(request, null);
        assertNull(authenticationRequest);
    }

}