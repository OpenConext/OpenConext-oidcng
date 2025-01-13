package oidc.saml;

import oidc.model.AuthenticationRequest;
import oidc.repository.AuthenticationRequestRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

public class ResponseAuthenticationValidator implements Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult> {

    private static final Log LOG = LogFactory.getLog(ResponseAuthenticationValidator.class);

    private final AuthenticationRequestRepository authenticationRequestRepository;
    private final Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult> defaultResponseValidator;

    public ResponseAuthenticationValidator(AuthenticationRequestRepository authenticationRequestRepository) {
        this.authenticationRequestRepository = authenticationRequestRepository;
        this.defaultResponseValidator =
                OpenSaml4AuthenticationProvider.createDefaultResponseValidator();
    }

    @Override
    public Saml2ResponseValidatorResult convert(OpenSaml4AuthenticationProvider.ResponseToken responseToken) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Validating responseToken %s, %s, %s",
                    responseToken.getResponse().getInResponseTo(),
                    responseToken.getToken().getPrincipal(),
                    responseToken.getToken().getAuthenticationRequest()));
        }
        try {
            Saml2ResponseValidatorResult result = defaultResponseValidator.convert(responseToken);
            if (result == null || result.hasErrors()) {
                LOG.warn("Saml2ResponseValidatorResult contains errors, find original authenticationRequest");
                if (result != null) {
                    result.getErrors().forEach(error -> LOG.warn(error.toString()));
                }
                return returnInvalidResult(responseToken);
            }
            return result;
        } catch (Saml2AuthenticationException e) {
            LOG.warn("Caught Saml2AuthenticationException, find original authenticationRequest");
            return returnInvalidResult(responseToken);
        }
    }

    private Saml2ResponseValidatorResult returnInvalidResult(OpenSaml4AuthenticationProvider.ResponseToken responseToken) {
        Response response = responseToken.getResponse();
        String inResponseTo = response.getInResponseTo();
        AuthenticationRequest authenticationRequest =
                authenticationRequestRepository.findById(inResponseTo).orElseThrow(() ->
                        new SessionAuthenticationException("Invalid Authn Statement. Missing InResponseTo"));
        String description = "Unknown exception has occurred";
        Status status = response.getStatus();
        if (status != null) {
            StatusMessage statusMessage = status.getStatusMessage();
            if (statusMessage != null) {
                description = statusMessage.getMessage();
            }
        }

        throw new ContextSaml2AuthenticationException(authenticationRequest, description);
    }

}
