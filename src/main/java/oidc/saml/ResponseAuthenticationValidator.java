package oidc.saml;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import oidc.model.AuthenticationRequest;
import oidc.model.User;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.UserRepository;
import oidc.user.OidcSamlAuthentication;
import oidc.user.UserAttribute;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.*;
import org.opensaml.saml.saml2.core.*;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.Resource;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;

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
        try {
            return defaultResponseValidator.convert(responseToken);
        } catch (Saml2AuthenticationException e) {
            LOG.info("Caught Saml2AuthenticationException, find original authenticationRequest");
            String inResponseTo = responseToken.getResponse().getInResponseTo();
            AuthenticationRequest authenticationRequest = authenticationRequestRepository.findById(inResponseTo).orElseThrow(() -> new SessionAuthenticationException("Invalid Authn Statement. Missing InResponseTo"));
            String description = responseToken.getResponse().getStatus().getStatusMessage().getValue();
            throw new ContextSaml2AuthenticationException(authenticationRequest, description);
        }
    }

}
