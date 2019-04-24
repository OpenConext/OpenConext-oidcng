package oidc.endpoints;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import oidc.exceptions.RedirectMismatchException;
import oidc.manage.Manage;
import oidc.model.AuthorizationCode;
import oidc.model.OpenIDClient;
import oidc.repository.AuthorizationCodeRepository;
import oidc.secure.TokenGenerator;
import oidc.user.OidcSamlAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.stream.Collectors;

@Controller
public class AuthorizationEndpoint {

    private Manage manage;
    private AuthorizationCodeRepository authorizationCodeRepository;

    @Autowired
    public AuthorizationEndpoint(Manage manage, AuthorizationCodeRepository authorizationCodeRepository) {
        this.manage = manage;
        this.authorizationCodeRepository = authorizationCodeRepository;
    }

    @GetMapping("/oidc/authorize")
    public View authorize(@RequestParam MultiValueMap<String, String> parameters,
                          Authentication authentication) throws ParseException {
        return doAuthorize(parameters, authentication);
    }

    private View doAuthorize(@RequestParam MultiValueMap<String, String> parameters, Authentication authentication) throws ParseException {
        OidcSamlAuthentication samlAuthentication = (OidcSamlAuthentication) authentication;
        AuthenticationRequest authenticationRequest = AuthenticationRequest.parse(parameters);
        Scope scope = authenticationRequest.getScope();
        State state = authenticationRequest.getState();
        ResponseType responseType = authenticationRequest.getResponseType();
        ClientID clientID = authenticationRequest.getClientID();
        OpenIDClient client = manage.client(clientID.getValue());

        List<String> scopes = scope.toStringList();
        scopes = scopes.stream().filter(s -> client.getScopes().contains(s)).collect(Collectors.toList());

        String redirectionURI = authenticationRequest.getRedirectionURI().toString();
        if (!client.getRedirectUrls().contains(redirectionURI)) {
            throw new RedirectMismatchException(
                    String.format("Client %s with registered redirect URI's %s requested authorization with redirectURI %s",
                            client.getClientId(), client.getRedirectUrls(), redirectionURI));
        }
        if (responseType.impliesCodeFlow()) {
            //Store everything we need along side with the authorization code
            String code = TokenGenerator.generateAuthorizationCode();
            AuthorizationCode authorizationCode = new AuthorizationCode(
                    code, samlAuthentication.getUser().getId(), client.getClientId(), scopes, redirectionURI);
            authorizationCodeRepository.insert(authorizationCode);

            return new RedirectView(authorizationRedirect(redirectionURI, state, code));
        } else if (responseType.impliesImplicitFlow()) {

//            AccessToken accessToken = new AccessToken()
        }
        throw new IllegalArgumentException("Not yet implemented response_type: " + responseType.toString());
    }

    private String authorizationRedirect(String redirectURI, State state, String code) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectURI).queryParam("code", code);
        if (state != null && StringUtils.hasText(state.getValue())) {
            builder.queryParam("state", state.getValue());
        }
        return builder.toUriString();
    }
}
