package oidc.saml;

import oidc.model.SamlAuthenticationRequest;
import oidc.repository.SamlAuthenticationRequestRepository;
import org.apache.commons.codec.CodecPolicy;
import org.apache.commons.codec.binary.Base64;
import org.springframework.http.HttpMethod;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import static oidc.saml.ResponseAuthenticationConverter.idPattern;
import static oidc.saml.ResponseAuthenticationConverter.inResponseToPattern;


@SuppressWarnings("deprecation")
public class MongoSaml2AuthenticationRequestRepository implements Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> {

    private final SamlAuthenticationRequestRepository samlAuthenticationRequestRepository;
    private final RelyingPartyRegistration relyingPartyRegistration;
    private static final Base64 BASE64 = new Base64(0, new byte[]{'\n'}, false, CodecPolicy.STRICT);

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
        String samlRequest = redirectAuthenticationRequest.getSamlRequest();
        String authenticationRequestID = this.getAuthenticationRequestID(samlRequest, true, request);
        SamlAuthenticationRequest samlAuthenticationRequest = new SamlAuthenticationRequest(
                authenticationRequestID,
                samlRequest,
                redirectAuthenticationRequest.getSigAlg(),
                redirectAuthenticationRequest.getSignature(),
                redirectAuthenticationRequest.getRelayState(),
                redirectAuthenticationRequest.getAuthenticationRequestUri(),
                new Date()
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
        String saml2Response = request.getParameter(Saml2ParameterNames.SAML_RESPONSE);
        if (saml2Response == null) {
            return null;
        }
        String authenticationRequestID = this.getAuthenticationRequestID(saml2Response, false, request);
        return samlAuthenticationRequestRepository.findById(authenticationRequestID).orElse(null);
    }

    private String samlInflate(byte[] b) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            InflaterOutputStream inflaterOutputStream = new InflaterOutputStream(out, new Inflater(true));
            inflaterOutputStream.write(b);
            inflaterOutputStream.finish();
            return out.toString(StandardCharsets.UTF_8.name());
        } catch (Exception ex) {
            throw new Saml2AuthenticationException(
                    new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Unable to inflate string"), ex);
        }
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

    private String getAuthenticationRequestID(String saml, boolean isAuthnRequest, HttpServletRequest request) {
        byte[] bytes = BASE64.decode(saml);
        String inflatedSaml = HttpMethod.GET.matches(request.getMethod()) ? samlInflate(bytes)
                : new String(bytes, StandardCharsets.UTF_8);
        Matcher matcher = (isAuthnRequest ? idPattern : inResponseToPattern).matcher(inflatedSaml);
        boolean match = matcher.find();
        if (!match) {
            throw new SessionAuthenticationException("Invalid Authn Statement. Missing " + (isAuthnRequest ? "ID" : "InResponseTo"));
        }
        return matcher.group(1);
    }

}
