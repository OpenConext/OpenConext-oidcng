package oidc.api;

import oidc.crypto.KeyGenerator;
import oidc.model.AccessToken;
import oidc.model.OpenIDClient;
import oidc.model.RefreshToken;
import oidc.model.Scope;
import oidc.model.TokenRepresentation;
import oidc.model.TokenType;
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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
public class TokenController {

    private static final Log LOG = LogFactory.getLog(TokenController.class);

    private AccessTokenRepository accessTokenRepository;
    private RefreshTokenRepository refreshTokenRepository;
    private OpenIDClientRepository openIDClientRepository;
    private String salt;

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
    public List<Map<String, Object>> tokens(Authentication authentication, @RequestParam("unspecifiedID") String unspecifiedId) throws UnsupportedEncodingException {
        String name = authentication.getName();
        unspecifiedId = URLDecoder.decode(unspecifiedId, Charset.defaultCharset().name());

        LOG.debug(String.format("Starting tokens GET for %s with unspecified %s", name, unspecifiedId));

        String unspecifiedUrnHash = KeyGenerator.oneWayHash(unspecifiedId, salt);

        List<AccessToken> accessTokens = accessTokenRepository.findAccessTokenByUnspecifiedUrnHash(unspecifiedUrnHash);
        List<RefreshToken> refreshTokens = refreshTokenRepository.findAccessTokenByUnspecifiedUrnHash(unspecifiedUrnHash);

        accessTokens.addAll(refreshTokens);
        List<Map<String, Object>> result = accessTokens.stream()
                .map(this::convertToken)
                //No use returning tokens without RP
                .filter(map -> map.containsKey("clientName"))
                .collect(Collectors.toList());

        LOG.debug(String.format("Returning tokens for %s with unspecified %s: %s", name, unspecifiedId, result));

        return result;
    }

    @PutMapping("tokens")
    @PreAuthorize("hasRole('ROLE_api_tokens')")
    public ResponseEntity<Void> deleteTokens(Authentication authentication,
                                             @RequestBody List<TokenRepresentation> tokenIdentifiers) {
        String name = authentication.getName();

        LOG.debug(String.format("Deleting tokens for %s with token(s) %s", name, tokenIdentifiers));

        tokenIdentifiers.stream().forEach(tokenRepresentation ->
                (tokenRepresentation.getTokenType().equals(TokenType.ACCESS) ? accessTokenRepository : refreshTokenRepository)
                        .deleteById(tokenRepresentation.getId()));

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    private Map<String, Object> convertToken(AccessToken token) {
        Map<String, Object> result = new HashMap<>();
        result.put("id", token.getId());

        Optional<OpenIDClient> optionalClient = openIDClientRepository.findOptionalByClientId(token.getClientId());
        optionalClient.ifPresent(openIDClient -> {
            result.put("clientId", openIDClient.getClientId());
            result.put("clientName", openIDClient.getName());
            result.put("audiences", openIDClient.getAllowedResourceServers().stream()
                    .map(rs -> openIDClientRepository.findOptionalByClientId(rs))
                    .filter(Optional::isPresent)
                    .map(opt -> opt.get().getName()));
        });
        result.put("createdAt", token.getCreatedAt());
        result.put("expiresIn", token.getExpiresIn());
        result.put("type", token instanceof RefreshToken ? TokenType.REFRESH : TokenType.ACCESS);

        List<Scope> scopes = token.getScopes().stream().map(scope -> scope(scope, optionalClient)).collect(Collectors.toList());
        result.put("scopes", scopes);
        return result;
    }

    private Scope scope(String name, Optional<OpenIDClient> clientOptional) {
        Scope scope = new Scope(name);
        clientOptional.ifPresent(openIDClient -> openIDClient.getScopes().stream()
                .filter(s -> s.getName().equals(name)).findFirst()
                .ifPresent(s -> scope.setDescriptions(s.getDescriptions())));
        return scope;
    }

}
