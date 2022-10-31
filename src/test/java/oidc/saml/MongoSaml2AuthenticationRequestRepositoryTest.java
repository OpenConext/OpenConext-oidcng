package oidc.saml;

import oidc.model.SamlAuthenticationRequest;
import oidc.repository.SamlAuthenticationRequestRepository;
import org.apache.groovy.util.ObjectHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.*;

class MongoSaml2AuthenticationRequestRepositoryTest extends AbstractSamlUnitTest {

    private final SamlAuthenticationRequestRepository samlAuthenticationRequestRepository = mock(SamlAuthenticationRequestRepository.class);

    private final MongoSaml2AuthenticationRequestRepository subject = new MongoSaml2AuthenticationRequestRepository(samlAuthenticationRequestRepository, relyingParty);

    @BeforeEach
    public void before() {
        reset(samlAuthenticationRequestRepository);
    }

    @Test
    void authenticationRequestFlow() {
        Saml2RedirectAuthenticationRequest authenticationRequest = Saml2RedirectAuthenticationRequest
                .withRelyingPartyRegistration(relyingParty)
                .signature("signature")
                .sigAlg("sigAlg")
                .relayState("relaySate")
                .samlRequest("samlRequest")
                .build();
        HttpServletRequest request = new MockHttpServletRequest();
        ObjectHolder<SamlAuthenticationRequest> argumentObjectHolder = new ObjectHolder<>();
        when(samlAuthenticationRequestRepository.save(any())).thenAnswer(i -> {
            SamlAuthenticationRequest argument = i.getArgument(0);
            argumentObjectHolder.setObject(argument);
            return argument;
        });
        subject.saveAuthenticationRequest(authenticationRequest, request, null);

        when(samlAuthenticationRequestRepository.findById(anyString())).thenReturn(Optional.of(argumentObjectHolder.getObject()));
        Saml2RedirectAuthenticationRequest result = (Saml2RedirectAuthenticationRequest) subject.loadAuthenticationRequest(request);
        assertEquals("samlRequest", result.getSamlRequest());

        result = (Saml2RedirectAuthenticationRequest) subject.removeAuthenticationRequest(request, null);
        assertEquals("samlRequest", result.getSamlRequest());
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