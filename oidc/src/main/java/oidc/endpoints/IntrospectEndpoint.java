package oidc.endpoints;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.JakartaServletUtils;
import jakarta.servlet.http.HttpServletRequest;
import oidc.eduid.AttributePseudonymisation;
import oidc.exceptions.UnauthorizedException;
import oidc.exceptions.UnknownClientException;
import oidc.log.MDCContext;
import oidc.model.AccessToken;
import oidc.model.OpenIDClient;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.secure.TokenGenerator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Clock;
import java.util.*;

@RestController
public class IntrospectEndpoint extends SecureEndpoint {

    private static final Log LOG = LogFactory.getLog(IntrospectEndpoint.class);

    private final AccessTokenRepository accessTokenRepository;
    private final OpenIDClientRepository openIDClientRepository;
    private final String issuer;
    private final TokenGenerator tokenGenerator;
    private final AttributePseudonymisation attributePseudonymisation;
    private final boolean enforceEduidResourceServerLinkedAccount;


    public IntrospectEndpoint(AccessTokenRepository accessTokenRepository,
                              OpenIDClientRepository openIDClientRepository,
                              TokenGenerator tokenGenerator,
                              AttributePseudonymisation attributePseudonymisation,
                              @Value("${sp.entity_id}") String issuer,
                              @Value("${features.enforce-eduid-resource-server-linked-account}") boolean enforceEduidResourceServerLinkedAccount) {
        this.accessTokenRepository = accessTokenRepository;
        this.openIDClientRepository = openIDClientRepository;
        this.tokenGenerator = tokenGenerator;
        this.attributePseudonymisation = attributePseudonymisation;
        this.issuer = issuer;
        this.enforceEduidResourceServerLinkedAccount = enforceEduidResourceServerLinkedAccount;

    }

    @PostMapping(value = {"oidc/introspect"}, consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ResponseEntity<Map<String, Object>> introspect(HttpServletRequest request) throws ParseException, IOException, java.text.ParseException {
        HTTPRequest httpRequest = JakartaServletUtils.createHTTPRequest(request);
        TokenIntrospectionRequest tokenIntrospectionRequest = TokenIntrospectionRequest.parse(httpRequest);
        ClientAuthentication clientAuthentication = tokenIntrospectionRequest.getClientAuthentication();
        String accessTokenValue = tokenIntrospectionRequest.getToken().getValue();

        //https://tools.ietf.org/html/rfc7662 is vague about the authorization requirements, but we enforce basic auth
        if (!(clientAuthentication instanceof PlainClientSecret)) {
            LOG.warn("No authentication present");
            throw new UnauthorizedException("Invalid user / secret");
        }
        String clientId = clientAuthentication.getClientID().getValue();
        OpenIDClient resourceServer = openIDClientRepository.findOptionalByClientId(clientId)
                .orElseThrow(() -> new UnknownClientException(clientId));
        MDCContext.mdcContext("action", "Introspect", "rp", resourceServer.getClientId(), "accessTokenValue", accessTokenValue);

        if (!secretsMatch((PlainClientSecret) clientAuthentication, resourceServer)) {
            LOG.warn("Secret does not match for RS " + resourceServer.getClientId());
            throw new UnauthorizedException("Invalid user / secret");
        }
        if (!resourceServer.isResourceServer()) {
            LOG.warn("RS required for not configured for RP " + resourceServer.getClientId());
            throw new UnauthorizedException("Requires ResourceServer");
        }

        Optional<SignedJWT> optionalSignedJWT = tokenGenerator.parseAndValidateSignedJWT(accessTokenValue);
        if (!optionalSignedJWT.isPresent()) {
            LOG.warn("Invalid access_token " + accessTokenValue);
            return ResponseEntity.ok(Collections.singletonMap("active", false));
        }
        SignedJWT signedJWT = optionalSignedJWT.get();
        String jwtId = signedJWT.getJWTClaimsSet().getJWTID();
        Optional<AccessToken> optionalAccessToken = accessTokenRepository.findByJwtId(jwtId);
        if (!optionalAccessToken.isPresent()) {
            LOG.warn("No access_token found " + accessTokenValue);
            return ResponseEntity.ok(Collections.singletonMap("active", false));
        }
        AccessToken accessToken = optionalAccessToken.get();
        if (accessToken.isExpired(Clock.systemDefaultZone())) {
            LOG.warn("Access token is expired " + accessTokenValue);
            return ResponseEntity.ok(Collections.singletonMap("active", false));
        }

        List<String> scopes = accessToken.getScopes();
        Map<String, Object> result = new TreeMap<>();
        boolean isUserAccessToken = !accessToken.isClientCredentials();

        if (isUserAccessToken) {
            OpenIDClient openIDClient = openIDClientRepository.findOptionalByClientId(accessToken.getClientId())
                    .orElseThrow(() -> new UnknownClientException(accessToken.getClientId()));
            if (!openIDClient.getClientId().equals(resourceServer.getClientId()) &&
                    !openIDClient.getAllowedResourceServers().contains(resourceServer.getClientId())) {
                throw new UnauthorizedException(
                        String.format("RP %s is not allowed to use the API of resource server %s. Allowed resource servers are %s",
                                accessToken.getClientId(), resourceServer.getClientId(), openIDClient.getAllowedResourceServers()));
            }
            User user = tokenGenerator.decryptAccessTokenWithEmbeddedUserInfo(signedJWT);
            result.put("updated_at", user.getUpdatedAt());
            if (resourceServer.isIncludeUnspecifiedNameID()) {
                result.put("unspecified_id", user.getUnspecifiedNameId());
            }
            result.put("authenticating_authority", user.getAuthenticatingAuthority());
            result.put("sub", user.getSub());
            result.putAll(user.getAttributes());
            List<String> acrClaims = user.getAcrClaims();
            if (!CollectionUtils.isEmpty(acrClaims)) {
                result.put("acr", String.join(" ", acrClaims));
            }

            boolean validPseudonymisation = validPseudonymisation(result, resourceServer, openIDClient);
            if (!validPseudonymisation && enforceEduidResourceServerLinkedAccount) {
                LOG.warn(String.format("Pseudonymisation failed. No eduperson_principal_name for RS %s", resourceServer.getClientId()));
                return ResponseEntity.ok(Collections.singletonMap("active", false));
            }
        }
        //The following claims can not be overridden by the
        result.put("active", true);
        result.put("scope", String.join(" ", scopes));
        result.put("client_id", accessToken.getClientId());
        result.put("exp", accessToken.getExpiresIn().getTime() / 1000L);
        result.put("sub", accessToken.getSub());
        result.put("iss", issuer);
        result.put("token_type", "Bearer");

        LOG.debug(String.format("Returning introspect active %s for RS %s", true, resourceServer.getClientId()));

        return ResponseEntity.ok(result);
    }

    @SuppressWarnings("unchecked")
    private boolean validPseudonymisation(Map<String, Object> userAttributes, OpenIDClient resourceServer, OpenIDClient openIDClient) {
        String eduId = (String) userAttributes.get("eduid");
        Map<String, String> pseudonymiseResult = attributePseudonymisation.pseudonymise(resourceServer, openIDClient, eduId)
            .orElseGet(Collections::emptyMap);
        if (pseudonymiseResult.containsKey("eduid") &&
            !pseudonymiseResult.containsKey("eduperson_principal_name")) {
            //The user is not linked to an IdP belonging to this RS - only replace the pseudo eduid and not other attributes
            userAttributes.put("eduid", pseudonymiseResult.get("eduid"));
            return false;
        }
        userAttributes.putAll(pseudonymiseResult);
        return true;
    }

}
