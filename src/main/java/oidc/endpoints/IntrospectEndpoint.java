package oidc.endpoints;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import oidc.eduid.AttributePseudonymisation;
import oidc.exceptions.UnauthorizedException;
import oidc.model.AccessToken;
import oidc.model.OpenIDClient;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.secure.TokenGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.Clock;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
public class IntrospectEndpoint extends SecureEndpoint implements OrderedMap {

    private final AccessTokenRepository accessTokenRepository;
    private final OpenIDClientRepository openIDClientRepository;
    private final String issuer;
    private final TokenGenerator tokenGenerator;
    private final AttributePseudonymisation attributePseudonymisation;

    public IntrospectEndpoint(AccessTokenRepository accessTokenRepository,
                              OpenIDClientRepository openIDClientRepository,
                              TokenGenerator tokenGenerator,
                              AttributePseudonymisation attributePseudonymisation,
                              @Value("${spring.security.saml2.service-provider.entity-id}") String issuer) {
        this.accessTokenRepository = accessTokenRepository;
        this.openIDClientRepository = openIDClientRepository;
        this.tokenGenerator = tokenGenerator;
        this.attributePseudonymisation = attributePseudonymisation;
        this.issuer = issuer;
    }

    @PostMapping(value = {"oidc/introspect"}, consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ResponseEntity<Map<String, Object>> introspect(HttpServletRequest request) throws ParseException, IOException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
        TokenIntrospectionRequest tokenIntrospectionRequest = TokenIntrospectionRequest.parse(httpRequest);
        ClientAuthentication clientAuthentication = tokenIntrospectionRequest.getClientAuthentication();
        String accessTokenValue = tokenIntrospectionRequest.getToken().getValue();

        //https://tools.ietf.org/html/rfc7662 is vague about the authorization requirements, but we enforce basic auth
        if (!(clientAuthentication instanceof PlainClientSecret)) {
            throw new BadCredentialsException("Invalid user / secret");
        }
        OpenIDClient resourceServer = openIDClientRepository.findByClientId(clientAuthentication.getClientID().getValue());

        if (!secretsMatch((PlainClientSecret) clientAuthentication, resourceServer)) {
            throw new BadCredentialsException("Invalid user / secret");
        }
        if (!resourceServer.isResourceServer()) {
            throw new BadCredentialsException("Requires ResourceServer");
        }

        Optional<AccessToken> optionalAccessToken = accessTokenRepository.findOptionalAccessTokenByValue(accessTokenValue);
        if (!optionalAccessToken.isPresent()) {
            return ResponseEntity.ok(Collections.singletonMap("active", false));
        }
        AccessToken accessToken = optionalAccessToken.get();
        if (accessToken.isExpired(Clock.systemDefaultZone())) {
            return ResponseEntity.ok(Collections.singletonMap("active", false));
        }
        Map<String, Object> result = new HashMap<>();

        boolean isUserAccessToken = !accessToken.isClientCredentials();

        if (isUserAccessToken) {
            OpenIDClient openIDClient = openIDClientRepository.findByClientId(accessToken.getClientId());
            if (!openIDClient.getAllowedResourceServers().contains(resourceServer.getClientId())) {
                throw new UnauthorizedException(
                        String.format("RP %s is not allowed to use the API of resource server %s. Allowed resource servers are %s",
                                accessToken.getClientId(), resourceServer.getClientId(), openIDClient.getAllowedResourceServers()));
            }
            User user = tokenGenerator.decryptAccessTokenWithEmbeddedUserInfo(accessTokenValue);
            result.put("updated_at", user.getUpdatedAt());
            if (resourceServer.isIncludeUnspecifiedNameID()) {
                result.put("unspecified_id", user.getUnspecifiedNameId());
            }
            result.put("authenticating_authority", user.getAuthenticatingAuthority());
            result.put("sub", user.getSub());
            result.putAll(user.getAttributes());
            result = attributePseudonymisation.pseudonymise(resourceServer, openIDClient, result);
        }
        //The following claims can not be overridden by the
        result.put("active", true);
        result.put("scope", String.join(" ", accessToken.getScopes()));
        result.put("client_id", accessToken.getClientId());
        result.put("exp", accessToken.getExpiresIn().getTime() / 1000L);
        result.put("sub", accessToken.getSub());
        result.put("iss", issuer);
        result.put("token_type", "Bearer");

        return ResponseEntity.ok(sortMap(result));
    }

}
