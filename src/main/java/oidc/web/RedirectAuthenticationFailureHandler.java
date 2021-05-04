package oidc.web;

import lombok.SneakyThrows;
import oidc.endpoints.AuthorizationEndpoint;
import oidc.exceptions.UnknownClientException;
import oidc.model.OpenIDClient;
import oidc.repository.OpenIDClientRepository;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.util.CollectionUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static oidc.saml.AuthnRequestConverter.REDIRECT_URI_VALID;

public class RedirectAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final OpenIDClientRepository openIDClientRepository;

    public RedirectAuthenticationFailureHandler(OpenIDClientRepository openIDClientRepository) {
        this.openIDClientRepository = openIDClientRepository;
    }


    @SneakyThrows
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        DefaultSavedRequest savedRequest = (DefaultSavedRequest) request.getSession(false).getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        if (savedRequest != null) {
            Map<String, String[]> parameterMap = savedRequest.getParameterMap();
            Map<String, List<String>> parameters = parameterMap.keySet().stream()
                    .collect(Collectors.toMap(key -> key, key -> Arrays.asList(parameterMap.get(key))));

            List<String> redirectUris = parameters.get("redirect_uri");
            URI redirectURI = CollectionUtils.isEmpty(redirectUris) ? null : new URI(redirectUris.get(0));

            List<String> clientIds = parameters.get("client_id");
            String clientId = CollectionUtils.isEmpty(clientIds) ? null : clientIds.get(0);

            OpenIDClient openIDClient = openIDClientRepository.findOptionalByClientId(clientId).orElseThrow(UnknownClientException::new);
            AuthorizationEndpoint.validateRedirectionURI(redirectURI, openIDClient);
            request.setAttribute(REDIRECT_URI_VALID, true);
        }
        //Will be picked up by the ErrorController
        throw exception;
    }
}
