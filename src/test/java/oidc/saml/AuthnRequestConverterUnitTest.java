package oidc.saml;

import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.OpenIDClientRepository;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.savedrequest.RequestCache;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

import static org.mockito.Mockito.mock;

public class AuthnRequestConverterUnitTest {
    private OpenIDClientRepository openIDClientRepository = mock(OpenIDClientRepository.class);
    private AuthenticationRequestRepository authenticationRequestRepository = mock(AuthenticationRequestRepository.class);
    private RequestCache requestCache = mock(RequestCache.class);

    private AuthnRequestConverter subject = new AuthnRequestConverter(openIDClientRepository, authenticationRequestRepository, requestCache);

    @Test
    public void testSaml() throws IOException {
//        RelyingPartyRegistration relyingParty = RelyingPartyRegistration
//                .withRegistrationId("oidcng")
//                .entityId("entityID")
//                .assertionConsumerServiceLocation("https://acs")
//                .assertingPartyDetails(builder -> builder
//                        .entityId("entityID")
//                        .wantAuthnRequestsSigned(false)
//                        .singleSignOnServiceLocation("https://sso").build())
//                .build();
//        HttpServletRequest request = new MockHttpServletRequest();
//        CustomSaml2AuthenticationRequestContext ctx = new CustomSaml2AuthenticationRequestContext(relyingParty, request);
//        subject.convert(ctx);
    }

}