package oidc.endpoints;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import oidc.exceptions.RedirectMismatchException;
import oidc.manage.Manage;
import oidc.model.OpenIDClient;
import oidc.repository.AccessTokenRepository;
import oidc.secure.TokenGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
public class AuthorizationEndpoint {

    private Manage manage;
    private AccessTokenRepository accessTokenRepository;

    @Autowired
    public AuthorizationEndpoint(Manage manage, AccessTokenRepository accessTokenRepository) {
        this.manage = manage;
        this.accessTokenRepository = accessTokenRepository;
    }

    @GetMapping("authorize")
    public View authorize(@RequestParam MultiValueMap<String, String> parameters,
                          Authentication authentication) throws ParseException {
        return doAuthorize(parameters, (DefaultSamlAuthentication) authentication);
    }

    private View doAuthorize(@RequestParam MultiValueMap<String, String> parameters, DefaultSamlAuthentication authentication) throws ParseException {
        DefaultSamlAuthentication samlAuthentication = authentication;
        AuthenticationRequest authenticationRequest = AuthenticationRequest.parse(parameters);
        Scope scope = authenticationRequest.getScope();
        State state = authenticationRequest.getState();
        ResponseType responseType = authenticationRequest.getResponseType();
        ClientID clientID = authenticationRequest.getClientID();
        OpenIDClient client = manage.client(clientID.getValue());

        String redirectionURI = authenticationRequest.getRedirectionURI().toString();
        if (!client.getRedirectUrls().contains(redirectionURI)) {
            throw new RedirectMismatchException(
                    String.format("Client %s with registered redirect URI's %s requested authorization with redirectURI %s",
                            client.getClientId(), client.getRedirectUrls(), redirectionURI));
        }
        String code = TokenGenerator.repositoryId();
        return new RedirectView(authorizationRedirect(redirectionURI, state, code));
    }

    private String authorizationRedirect(String redirectURI, State state, String code) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectURI).queryParam("code", code);
        if (state != null && StringUtils.hasText(state.getValue())) {
            builder.queryParam("state", state.getValue());
        }
        return builder.toUriString();
    }
}
