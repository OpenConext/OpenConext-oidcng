package oidc.endpoints;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import oidc.model.AccessToken;
import oidc.model.OpenIDClient;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

@RestController
public class IntrospectEndpoint extends SecureEndpoint {

    private AccessTokenRepository accessTokenRepository;
    private UserRepository userRepository;
    private OpenIDClientRepository openIDClientRepository;
    private String issuer;

    public IntrospectEndpoint(AccessTokenRepository accessTokenRepository,
                              UserRepository userRepository,
                              OpenIDClientRepository openIDClientRepository,
                              @Value("${spring.security.saml2.service-provider.entity-id}") String issuer) {
        this.accessTokenRepository = accessTokenRepository;
        this.userRepository = userRepository;
        this.openIDClientRepository = openIDClientRepository;
        this.issuer = issuer;
    }

    @PostMapping(value = {"oidc/introspect"}, consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public Map<String, Object> introspect(HttpServletRequest request) throws ParseException, IOException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
        TokenIntrospectionRequest tokenIntrospectionRequest = TokenIntrospectionRequest.parse(httpRequest);
        ClientAuthentication clientAuthentication = tokenIntrospectionRequest.getClientAuthentication();
        String value = tokenIntrospectionRequest.getToken().getValue();
        //https://tools.ietf.org/html/rfc7662 is vague about the authorization requirements, but we enforce basic auth
        if (clientAuthentication == null || !(clientAuthentication instanceof PlainClientSecret)) {
            throw new BadCredentialsException("Invalid user / secret");
        }
        OpenIDClient client = openIDClientRepository.findByClientId(clientAuthentication.getClientID().getValue());

        if (!secretsMatch(PlainClientSecret.class.cast(clientAuthentication), client)) {
            throw new BadCredentialsException("Invalid user / secret");
        }
        if (!client.isResourceServer()) {
            throw new BadCredentialsException("Requires ResourceServer");
        }
        AccessToken accessToken = accessTokenRepository.findByValue(value);
        if (accessToken.getExpiresIn().before(new Date())) {
            return Collections.singletonMap("active", false);
        }
        User user = userRepository.findUserBySub(accessToken.getSub());

        Map<String, Object> attributes = user.getAttributes();
        attributes.put("updated_at", user.getUpdatedAt());
        attributes.put("unspecified_id", user.getUnspecifiedNameId());

        attributes.put("active", true);
        attributes.put("scope", String.join(",", accessToken.getScopes()));
        attributes.put("client_id", client.getClientId());
        attributes.put("exp", accessToken.getExpiresIn().getTime() / 1000L);
        attributes.put("sub", user.getSub());
        attributes.put("authenticating_authority", user.getAuthenticatingAuthority());
        attributes.put("iss", issuer);
        attributes.put("token_type", "Bearer");
        return attributes;
    }

}
