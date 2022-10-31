package oidc.saml;

import oidc.model.SamlAuthenticationRequest;
import oidc.repository.SamlAuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;


@SuppressWarnings("deprecation")
public class MongoSaml2AuthenticationRequestRepository implements Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> {

    private final SamlAuthenticationRequestRepository samlAuthenticationRequestRepository;
    private final RelyingPartyRegistration relyingPartyRegistration;

    public MongoSaml2AuthenticationRequestRepository(SamlAuthenticationRequestRepository samlAuthenticationRequestRepository, RelyingPartyRegistration relyingPartyRegistration) {
        this.samlAuthenticationRequestRepository = samlAuthenticationRequestRepository;
        this.relyingPartyRegistration = relyingPartyRegistration;
    }

    @Override
    public AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
        SamlAuthenticationRequest samlAuthenticationRequest = doLoadAuthenticationRequest(request);
        if (samlAuthenticationRequest == null) {
            return null;
        }
        return buildSaml2RedirectAuthenticationRequest(samlAuthenticationRequest);
    }

    @Override
    public void saveAuthenticationRequest(AbstractSaml2AuthenticationRequest authenticationRequest, HttpServletRequest request, HttpServletResponse response) {
        Saml2RedirectAuthenticationRequest redirectAuthenticationRequest = (Saml2RedirectAuthenticationRequest) authenticationRequest;
        SamlAuthenticationRequest samlAuthenticationRequest = new SamlAuthenticationRequest(
                request.getSession(true).getId(),
                redirectAuthenticationRequest.getSamlRequest(),
                redirectAuthenticationRequest.getSigAlg(),
                redirectAuthenticationRequest.getSignature(),
                redirectAuthenticationRequest.getRelayState(),
                redirectAuthenticationRequest.getAuthenticationRequestUri()
        );
        this.samlAuthenticationRequestRepository.save(samlAuthenticationRequest);
    }

    @Override
    public AbstractSaml2AuthenticationRequest removeAuthenticationRequest(HttpServletRequest request, HttpServletResponse response) {
        SamlAuthenticationRequest samlAuthenticationRequest = doLoadAuthenticationRequest(request);
        if (samlAuthenticationRequest == null) {
            return null;
        }
        this.samlAuthenticationRequestRepository.delete(samlAuthenticationRequest);
        return this.buildSaml2RedirectAuthenticationRequest(samlAuthenticationRequest);
    }

    private SamlAuthenticationRequest doLoadAuthenticationRequest(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        return samlAuthenticationRequestRepository.findById(session.getId()).orElse(null);
    }

    private Saml2RedirectAuthenticationRequest buildSaml2RedirectAuthenticationRequest(SamlAuthenticationRequest samlAuthenticationRequest) {
        return Saml2RedirectAuthenticationRequest
                .withRelyingPartyRegistration(this.relyingPartyRegistration)
                .signature(samlAuthenticationRequest.getSignature())
                .sigAlg(samlAuthenticationRequest.getSigAlg())
                .relayState(samlAuthenticationRequest.getRelayState())
                .samlRequest(samlAuthenticationRequest.getSamlRequest())
                .build();
    }

}
