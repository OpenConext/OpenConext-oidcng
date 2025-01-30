package oidc.web;

import lombok.SneakyThrows;
import oidc.endpoints.AuthorizationEndpoint;
import oidc.exceptions.UnknownClientException;
import oidc.model.AuthenticationRequest;
import oidc.model.OpenIDClient;
import oidc.repository.OpenIDClientRepository;
import oidc.saml.ContextSaml2AuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.CollectionUtils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static oidc.saml.AuthnRequestConverter.REDIRECT_URI_VALID;

public class RedirectAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final OpenIDClientRepository openIDClientRepository;
    private RequestCache requestCache = new HttpSessionRequestCache();

    public RedirectAuthenticationFailureHandler(OpenIDClientRepository openIDClientRepository) {
        this.openIDClientRepository = openIDClientRepository;
    }


    @SneakyThrows
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        HttpSession session = request.getSession(false);
        SavedRequest savedRequest = null;
        if (session != null) {
            savedRequest = (SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        }
        if (savedRequest == null) {
            savedRequest = requestCache.getRequest(request, response);
        }
        if (savedRequest != null) {
            Map<String, String[]> parameterMap = savedRequest.getParameterMap();
            Map<String, List<String>> parameters = parameterMap.keySet().stream()
                    .collect(Collectors.toMap(key -> key, key -> Arrays.asList(parameterMap.get(key))));

            List<String> redirectUris = parameters.get("redirect_uri");
            URI redirectURI = CollectionUtils.isEmpty(redirectUris) ? null : new URI(redirectUris.get(0));

            List<String> clientIds = parameters.get("client_id");
            String clientId = CollectionUtils.isEmpty(clientIds) ? null : clientIds.get(0);

            OpenIDClient openIDClient = openIDClientRepository.findOptionalByClientId(clientId)
                    .orElseThrow(() -> new UnknownClientException(clientId));
            AuthorizationEndpoint.validateRedirectionURI(redirectURI, openIDClient);
            request.setAttribute(REDIRECT_URI_VALID, true);
        } else if (exception instanceof ContextSaml2AuthenticationException) {
            request.setAttribute(REDIRECT_URI_VALID, true);
            throw exception;
        }
        /*
         * Will be picked up by the CustomErrorController. Do note that if the user has stepped up his account in eduID, then
         * the initial session is no longer around.
         */
        if (exception instanceof Saml2AuthenticationException) {
            throw new Saml2AuthenticationException(
                    new Saml2Error(Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR,
                            "The requesting service has indicated that the authenticated user is required to have validated attributes. Your institution has not provided this."),
                    "The requesting service has indicated that the authenticated user is required to have validated attributes. Your institution has not provided this.",
                    exception);
        }
        throw exception;
    }
}
