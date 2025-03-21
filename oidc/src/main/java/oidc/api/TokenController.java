package oidc.api;

import oidc.crypto.KeyGenerator;
import oidc.model.*;
import oidc.repository.AccessTokenRepository;
import oidc.repository.OpenIDClientRepository;
import oidc.repository.RefreshTokenRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

@RestController
public class TokenController {

    private static final Log LOG = LogFactory.getLog(TokenController.class);

    private final AccessTokenRepository accessTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final OpenIDClientRepository openIDClientRepository;
    private final String salt;

    public TokenController(AccessTokenRepository accessTokenRepository,
                           RefreshTokenRepository refreshTokenRepository,
                           OpenIDClientRepository openIDClientRepository,
                           @Value("${access_token_one_way_hash_salt}") String salt) {
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.openIDClientRepository = openIDClientRepository;
        this.salt = salt;
    }

    @GetMapping("tokens")
    @PreAuthorize("hasRole('ROLE_api_tokens')")
    public List<Map<String, Object>> tokens(Authentication authentication, @RequestParam("unspecifiedID") String unspecifiedId) {
        return doTokens(authentication, unspecifiedId, APIVersion.V1);
    }

    @GetMapping("v2/tokens")
    @PreAuthorize("hasRole('ROLE_api_tokens')")
    public List<Map<String, Object>> tokensV2(Authentication authentication, @RequestParam("unspecifiedID") String unspecifiedId) {
        return doTokens(authentication, unspecifiedId, APIVersion.V2);
    }

    private List<Map<String, Object>> doTokens(Authentication authentication, String unspecifiedId, APIVersion apiVersion) {
        String name = authentication.getName();
        unspecifiedId = URLDecoder.decode(unspecifiedId, Charset.defaultCharset());

        LOG.debug(String.format("Starting tokens GET for %s with unspecified %s", name, unspecifiedId));

        String unspecifiedUrnHash = KeyGenerator.oneWayHash(unspecifiedId, salt);

        List<AccessToken> accessTokens = accessTokenRepository.findByUnspecifiedUrnHash(unspecifiedUrnHash);
        List<RefreshToken> refreshTokens = refreshTokenRepository.findByUnspecifiedUrnHash(unspecifiedUrnHash);

        accessTokens.addAll(refreshTokens);
        List<Map<String, Object>> result = accessTokens.stream()
                .map(token -> this.convertToken(token, apiVersion))
                //No use returning tokens without RP
                .filter(map -> map.containsKey("clientName"))
                //Version 2 for Profile only returns tokens where there is actual an audience
                .filter(map -> APIVersion.V1.equals(apiVersion) || !((Collection) map.get("audiences")).isEmpty())
                .collect(toList());

        LOG.debug(String.format("Returning tokens for %s with unspecified %s: %s", name, unspecifiedId, result));

        return result;
    }

    @PutMapping({"tokens", "v2/tokens"})
    @PreAuthorize("hasRole('ROLE_api_tokens')")
    public ResponseEntity<Void> deleteTokens(Authentication authentication,
                                             @RequestBody List<TokenRepresentation> tokenIdentifiers) {
        String name = authentication.getName();

        LOG.debug(String.format("Deleting tokens for %s with token(s) %s", name, tokenIdentifiers));

        tokenIdentifiers.stream().forEach(tokenRepresentation ->
                (tokenRepresentation.getType().equals(TokenType.ACCESS) ? accessTokenRepository : refreshTokenRepository)
                        .deleteById(tokenRepresentation.getId()));

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    private Map<String, Object> convertToken(AccessToken token, APIVersion version) {
        Map<String, Object> result = new HashMap<>();
        result.put("id", token.getId());

        Optional<OpenIDClient> optionalClient = openIDClientRepository.findOptionalByClientId(token.getClientId());
        if (optionalClient.isEmpty()) {
            return result;
        }
        OpenIDClient openIDClient = optionalClient.get();
        result.put("clientId", openIDClient.getClientId());
        result.put("clientName", openIDClient.getName());
        result.put("createdAt", token.getCreatedAt());
        result.put("expiresIn", token.getExpiresIn());
        result.put("type", token instanceof RefreshToken ? TokenType.REFRESH : TokenType.ACCESS);

        List<OpenIDClient> resourceServers = openIDClient.getAllowedResourceServers().stream()
                .map(openIDClientRepository::findOptionalByClientId)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(toList());

        if (version.equals(APIVersion.V1)) {
            result.put("audiences", resourceServers.stream().map(OpenIDClient::getName).collect(toList()));
            Map<String, Scope> allScopes = getAllScopes(resourceServers);
            List<Scope> scopes = token.getScopes().stream()
                    .filter(name -> !name.equalsIgnoreCase("openid"))
                    .map(allScopes::get)
                    .filter(Objects::nonNull)
                    .collect(toList());
            result.put("scopes", scopes);
        } else if (version.equals(APIVersion.V2)) {
            result.put("audiences", this.resourceServersObjects(token, resourceServers));
        }
        return result;
    }

    private Map<String, Scope> getAllScopes(List<OpenIDClient> resourceServers) {
        return resourceServers.stream().map(OpenIDClient::getScopes)
                .flatMap(List::stream)
                .filter(distinctByKey(Scope::getName))
                .collect(toMap(Scope::getName, s -> s));
    }

    private List<Map<String, Object>> resourceServersObjects(AccessToken token, List<OpenIDClient> resourceServers) {
        return resourceServers.stream()
                .map(rs -> Map.of(
                        "name:en", safeNotNotValue(rs.getName()),
                        "name:nl", safeNotNotValue(rs.getNameNl()),
                        "description:en", safeNotNotValue(rs.getDescription()),
                        "description:nl", safeNotNotValue(rs.getDescriptionNl()),
                        "OrganizationName:en:", safeNotNotValue(rs.getOrganisationName()),
                        "OrganizationName:nl:", safeNotNotValue(rs.getOrganisationNameNl()),
                        //Only add the scopes that are actually requested / granted for this token
                        "scopes", rs.getScopes().stream()
                                .filter(scope -> token.getScopes().contains(scope.getName()) &&
                                        !scope.getName().equalsIgnoreCase("openid"))
                                .collect(toList())
                ))
                .filter(map -> !((Collection) map.get("scopes")).isEmpty())
                .collect(toList());
    }

    private String safeNotNotValue(String value) {
        return StringUtils.hasText(value) ? value : "";
    }

    private <T> Predicate<T> distinctByKey(Function<? super T, ?> keyExtractor) {
        Set<Object> seen = ConcurrentHashMap.newKeySet();
        return t -> seen.add(keyExtractor.apply(t));
    }

}
