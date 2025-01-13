package oidc.endpoints;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.device.DeviceCodeGrant;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import oidc.crypto.KeyGenerator;
import oidc.exceptions.*;
import oidc.log.MDCContext;
import oidc.model.AuthorizationCode;
import oidc.model.*;
import oidc.repository.*;
import oidc.secure.JWTRequest;
import oidc.secure.TokenGenerator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hc.core5.http.ContentType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static oidc.endpoints.AuthorizationEndpoint.validateScopes;

@RestController
public class TokenEndpoint extends SecureEndpoint implements OidcEndpoint {

    private static final Log LOG = LogFactory.getLog(TokenEndpoint.class);

    private static final Pattern uuidPattern = Pattern.compile("[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}");

    private final ConcurrentAuthorizationCodeRepository concurrentAuthorizationCodeRepository;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final AccessTokenRepository accessTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final OpenIDClientRepository openIDClientRepository;
    private final DeviceAuthorizationRepository deviceAuthorizationRepository;
    private final TokenGenerator tokenGenerator;
    private final String tokenEndpoint;
    private final String salt;
    private final HttpHeaders responseHttpHeaders;

    public TokenEndpoint(OpenIDClientRepository openIDClientRepository,
                         AuthorizationCodeRepository authorizationCodeRepository,
                         ConcurrentAuthorizationCodeRepository concurrentAuthorizationCodeRepository,
                         AccessTokenRepository accessTokenRepository,
                         RefreshTokenRepository refreshTokenRepository,
                         UserRepository userRepository,
                         DeviceAuthorizationRepository deviceAuthorizationRepository,
                         TokenGenerator tokenGenerator,
                         @Value("${oidc_token_endpoint}") String tokenEndpoint,
                         @Value("${access_token_one_way_hash_salt}") String salt) {
        this.openIDClientRepository = openIDClientRepository;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.concurrentAuthorizationCodeRepository = concurrentAuthorizationCodeRepository;
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.deviceAuthorizationRepository = deviceAuthorizationRepository;
        this.tokenGenerator = tokenGenerator;
        this.tokenEndpoint = tokenEndpoint;
        this.salt = salt;
        this.responseHttpHeaders = this.getResponseHeaders();
    }

    @PostMapping(value = "oidc/token", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ResponseEntity token(HttpServletRequest request) throws IOException, ParseException, JOSEException, java.text.ParseException, CertificateException, BadJOSEException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
        TokenRequest tokenRequest = TokenRequest.parse(httpRequest);
        AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();

        ClientAuthentication clientAuthentication = getClientAuthentication(tokenRequest, authorizationGrant);
        String clientId = clientAuthentication != null ? clientAuthentication.getClientID().getValue() : tokenRequest.getClientID().getValue();
        OpenIDClient client = openIDClientRepository.findOptionalByClientId(clientId).orElseThrow(() -> new UnknownClientException(clientId));

        if (authorizationGrant instanceof DeviceCodeGrant) {
            DeviceCodeGrant deviceCodeGrant = (DeviceCodeGrant) authorizationGrant;
            String value = deviceCodeGrant.getDeviceCode().getValue();
            return deviceAuthorizationRepository.findByDeviceCode(value)
                    .map(deviceAuthorization ->  this.handleDeviceCodeFlow(deviceAuthorization, client))
                    .orElseThrow(() -> new DeviceFlowException("expired_token"));
        }

        if (clientAuthentication == null && !client.isPublicClient()) {
            throw new UnauthorizedException("Non-public client requires authentication");
        }
        if (clientAuthentication != null) {
            if (clientAuthentication instanceof PlainClientSecret &&
                    !secretsMatch((PlainClientSecret) clientAuthentication, client)) {
                throw new UnauthorizedException("Invalid user / secret");
            } else if (clientAuthentication instanceof JWTAuthentication &&
                    !verifySignature((JWTAuthentication) clientAuthentication, client, this.tokenEndpoint)) {
                throw new UnauthorizedException("Invalid user / signature");
            }
        }
        MDCContext.mdcContext("action", "Token", "rp", clientId, "grant", authorizationGrant.getType().getValue());
        if (!client.getGrants().contains(authorizationGrant.getType().getValue())) {
            throw new InvalidGrantException("Invalid grant: " + authorizationGrant.getType().getValue());
        }

        if (authorizationGrant instanceof AuthorizationCodeGrant) {
            return handleAuthorizationCodeGrant((AuthorizationCodeGrant) authorizationGrant, client);
        } else if (authorizationGrant instanceof ClientCredentialsGrant) {
            return handleClientCredentialsGrant(client, tokenRequest);
        } else if (authorizationGrant instanceof RefreshTokenGrant) {
            return handleRefreshCodeGrant((RefreshTokenGrant) authorizationGrant, client);
        }
        throw new IllegalArgumentException("Not supported - yet - authorizationGrant " + authorizationGrant.getType().getValue());

    }

    private ClientAuthentication getClientAuthentication(TokenRequest tokenRequest, AuthorizationGrant authorizationGrant) {
        ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();
        if (clientAuthentication != null &&
                !(clientAuthentication instanceof PlainClientSecret ||
                        clientAuthentication instanceof JWTAuthentication)) {
            throw new IllegalArgumentException(
                    String.format("Unsupported '%s' findByClientId authentication in token endpoint", clientAuthentication.getClass()));
        }
        if (clientAuthentication == null && authorizationGrant instanceof AuthorizationCodeGrant
                && ((AuthorizationCodeGrant) authorizationGrant).getCodeVerifier() == null) {
            throw new CodeVerifierMissingException("code_verifier required without client authentication");
        }
        return clientAuthentication;
    }

    boolean verifySignature(JWTAuthentication jwtAuthentication, OpenIDClient openIDClient, String tokenEndpoint)
            throws JOSEException, java.text.ParseException, CertificateException, IOException, BadJOSEException {
        Optional<JWTClaimsSet> jwtClaimsSetOptional = jwtClaimsSet(openIDClient, jwtAuthentication);
        if (!jwtClaimsSetOptional.isPresent()) {
            return false;
        }
        JWTClaimsSet claimsSet = jwtClaimsSetOptional.get();
        //https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-10
        if (!openIDClient.getClientId().equals(claimsSet.getIssuer())) {
            throw new JWTAuthorizationGrantsException("Invalid issuer");
        }
        if (!openIDClient.getClientId().equals(claimsSet.getSubject())) {
            throw new JWTAuthorizationGrantsException("Invalid subject");
        }
        if (!claimsSet.getAudience().contains(tokenEndpoint)) {
            throw new JWTAuthorizationGrantsException("Invalid audience");
        }
        if (new Date().after(claimsSet.getExpirationTime())) {
            throw new JWTAuthorizationGrantsException("Expired claims");
        }
        return true;
    }

    private Optional<JWTClaimsSet> jwtClaimsSet(OpenIDClient openIDClient, JWTAuthentication jwtAuthentication) throws IOException, BadJOSEException, CertificateException, java.text.ParseException, JOSEException {
        SignedJWT clientAssertion = jwtAuthentication.getClientAssertion();
        if (jwtAuthentication instanceof ClientSecretJWT) {
            MACVerifier macVerifier = new MACVerifier(openIDClient.getClientSecretJWT());
            return clientAssertion.verify(macVerifier) ? Optional.of(clientAssertion.getJWTClaimsSet()) : Optional.empty();
        }
        return Optional.of(JWTRequest.claimsSet(openIDClient, clientAssertion));
    }

    private ResponseEntity handleAuthorizationCodeGrant(AuthorizationCodeGrant authorizationCodeGrant, OpenIDClient client) {
        String code = authorizationCodeGrant.getAuthorizationCode().getValue();
        MDCContext.mdcContext("code", "code");
        AuthorizationCode authorizationCode = concurrentAuthorizationCodeRepository.findByCodeNotAlreadyUsedAndMarkAsUsed(code);

        if (authorizationCode == null) {
            /*
             * Now it becomes tricky. Did we get an 'null' because the code was bogus or because it was already
             * used? To both satisfy the - highly theoretical - risk of the audit race condition and the OIDC certification
             * demand of deleting access_token issued with the re-used authorization code we need to query again.
             *
             * If they code was bogus this will result in a 404 exception by the authorizationCodeRepository#findByCode
             * and if we find something then we know there was a re-use issue.
             */
            AuthorizationCode byCode;
            try {
                byCode = authorizationCodeRepository.findByCode(code);
            } catch (EmptyResultDataAccessException e) {
                throw new UnknownCodeException("Invalid code: " + code);
            }
            List<AccessToken> accessTokens = accessTokenRepository.findByAuthorizationCodeId(byCode.getId());
            accessTokenRepository.deleteAll(accessTokens);
            throw new TokenAlreadyUsedException(
                    String.format("Authorization code %s already used for RP %s, deleting access_tokens %s",
                            code,
                            client.getClientId(),
                            accessTokens.stream().map(AccessToken::getJwtId)
                                    .collect(Collectors.joining(", "))));
        }

        if (!authorizationCode.getClientId().equals(client.getClientId())) {
            throw new UnauthorizedException("Client is not authorized for the authorization code");
        }

        if (authorizationCodeGrant.getRedirectionURI() != null &&
                !authorizationCodeGrant.getRedirectionURI().toString().equals(authorizationCode.getRedirectUri())) {
            throw new RedirectMismatchException(
                    String.format("Client %s authorizationCodeGrant redirect URL %s does not match redirect URL %s from authorizationCode",
                            client.getClientId(), authorizationCodeGrant.getRedirectionURI(), authorizationCode.getRedirectUri()));
        }

        if (authorizationCode.isRedirectURIProvided() && authorizationCodeGrant.getRedirectionURI() == null) {
            throw new RedirectMismatchException(String.format("Client %s redirect URI is mandatory if specified in code request", client.getClientId()));
        }

        if (authorizationCode.isExpired(Clock.systemDefaultZone())) {
            throw new UnauthorizedException("Authorization code expired");
        }

        CodeVerifier codeVerifier = authorizationCodeGrant.getCodeVerifier();
        String codeChallenge = authorizationCode.getCodeChallenge();
        if (codeVerifier != null) {
            if (codeChallenge == null) {
                throw new CodeVerifierMissingException("code_verifier present, but no code_challenge in the authorization_code");
            }
            CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.parse(authorizationCode.getCodeChallengeMethod());
            CodeChallenge computed = CodeChallenge.compute(codeChallengeMethod, codeVerifier);

            //Constant time comparison
            if (!MessageDigest.isEqual(codeChallenge.getBytes(), computed.getValue().getBytes())) {
                LOG.error(String.format("CodeVerifier %s with method %s does not match codeChallenge %s. Expected codeChallenge is %s",
                        codeVerifier.getValue(), codeChallengeMethod, codeChallenge, computed.getValue()));
                throw new CodeVerifierMissingException("code_verifier does not match code_challenge");
            }
        }
        User user = userRepository.findUserBySub(authorizationCode.getSub());
        MDCContext.mdcContext(user);
        //User information is encrypted in access token
        LOG.debug("Deleting user " + user.getSub());
        userRepository.delete(user);

        Map<String, Object> body = tokenEndpointResponse(Optional.of(user), client, authorizationCode.getScopes(),
                authorizationCode.getIdTokenClaims(), false, authorizationCode.getNonce(),
                Optional.of(authorizationCode.getAuthTime()), Optional.of(authorizationCode.getId()));
        return new ResponseEntity<>(body, responseHttpHeaders, HttpStatus.OK);
    }

    private ResponseEntity handleDeviceCodeFlow(DeviceAuthorization deviceAuthorization, OpenIDClient client) {
        if (!client.getClientId().equals(deviceAuthorization.getClientId())) {
            throw new DeviceFlowException("access_denied");
        }
        if (!deviceAuthorization.getStatus().equals(DeviceAuthorizationStatus.success)) {
            Instant lastLookup = deviceAuthorization.getLastLookup();
            deviceAuthorization.setLastLookup(Instant.now());
            deviceAuthorizationRepository.save(deviceAuthorization);
            if (lastLookup != null && ((lastLookup.toEpochMilli() + 1001) > System.currentTimeMillis())) {
                throw new DeviceFlowException("slow_down");
            }
            throw new DeviceFlowException("authorization_pending");
        }
        User user = userRepository.findUserBySub(deviceAuthorization.getUserSub());
        MDCContext.mdcContext(user);
        //User information is encrypted in access token
        LOG.debug(String.format("Deleting user %s before token is returned for client %s",
                user.getSub(), client.getName()));

        userRepository.delete(user);

        Map<String, Object> body = tokenEndpointResponse(
                Optional.of(user),
                client,
                deviceAuthorization.getScopes(),
                Collections.emptyList(),
                false,
                null,
                Optional.of(System.currentTimeMillis() / 1000L),
                Optional.empty());
        //We only permit one request for a success authorization
        LOG.debug(String.format("Deleting deviceAuthorization as token is returned for client %s", client.getName()));
        deviceAuthorizationRepository.delete(deviceAuthorization);

        return new ResponseEntity<>(body, responseHttpHeaders, HttpStatus.OK);

    }

    private ResponseEntity handleRefreshCodeGrant(RefreshTokenGrant refreshTokenGrant, OpenIDClient client) throws java.text.ParseException {
        String refreshTokenValue = refreshTokenGrant.getRefreshToken().getValue();
        RefreshToken refreshToken;
        SignedJWT signedJWT = null;
        boolean oldFormat = uuidPattern.matcher(refreshTokenValue).matches();
        if (oldFormat) {
            //Old refreshToken
            refreshToken = refreshTokenRepository.findByInnerValue(refreshTokenValue);
        } else {
            Optional<SignedJWT> optionalSignedJWT = tokenGenerator.parseAndValidateSignedJWT(refreshTokenValue);
            signedJWT = optionalSignedJWT.orElseThrow(() -> new UnauthorizedException("Invalid refresh_token value"));
            String jwtId = signedJWT.getJWTClaimsSet().getJWTID();
            refreshToken = refreshTokenRepository.findByJwtId(jwtId)
                    .orElseThrow(() -> new IllegalArgumentException("RefreshToken not found"));
        }

        if (!refreshToken.getClientId().equals(client.getClientId())) {
            throw new InvalidClientException("Client is not authorized for the refresh token");
        }
        if (refreshToken.isExpired(Clock.systemDefaultZone())) {
            throw new UnauthorizedException("Refresh token expired");
        }

        //New tokens will be issued
        refreshTokenRepository.delete(refreshToken);
        //It is possible that the access token is already removed by cron cleanup actions
        Optional<AccessToken> accessToken;
        if (oldFormat) {
            //It is possible that the access token is already removed by cron cleanup actions
            accessToken = accessTokenRepository.findOptionalAccessTokenByValue(refreshToken.getAccessTokenValue());
        } else {
            accessToken = accessTokenRepository.findById(refreshToken.getAccessTokenId());
        }
        accessToken.ifPresent(oldAccessToken -> {
            LOG.info(String.format(
                    "Deleting existing access_token (jti: %s) after refresh_token request from %s",
                    oldAccessToken.getJwtId(),
                    client.getClientId()));
            accessTokenRepository.delete(oldAccessToken);
        });

        Optional<User> optionalUser;
        if (refreshToken.isClientCredentials()) {
            optionalUser = Optional.empty();
        } else if (oldFormat) {
            optionalUser = Optional.of(tokenGenerator.decryptAccessTokenWithEmbeddedUserInfo(refreshToken.getAccessTokenValue()));
        } else {
            optionalUser = Optional.of(tokenGenerator.decryptAccessTokenWithEmbeddedUserInfo(signedJWT));
        }
        Map<String, Object> body = tokenEndpointResponse(optionalUser, client, refreshToken.getScopes(),
                Collections.emptyList(), false, null, optionalUser.map(User::getUpdatedAt), Optional.empty());
        return new ResponseEntity<>(body, responseHttpHeaders, HttpStatus.OK);
    }

    private ResponseEntity handleClientCredentialsGrant(OpenIDClient client, TokenRequest tokenRequest) {
        List<String> scopes = validateScopes(openIDClientRepository, tokenRequest.getScope(), client);
        Map<String, Object> body = tokenEndpointResponse(Optional.empty(), client, scopes,
                Collections.emptyList(), true, null, Optional.empty(), Optional.empty());
        LOG.debug("Returning client_credentials access_token for RS " + client.getClientId());
        return new ResponseEntity<>(body, responseHttpHeaders, HttpStatus.OK);
    }

    private Map<String, Object> tokenEndpointResponse(Optional<User> user,
                                                      OpenIDClient client,
                                                      List<String> scopes,
                                                      List<String> idTokenClaims,
                                                      boolean clientCredentials,
                                                      String nonce,
                                                      Optional<Long> authorizationTime,
                                                      Optional<String> authorizationCodeId) {
        Map<String, Object> map = new LinkedHashMap<>();
        EncryptedTokenValue encryptedAccessToken = user
                .map(u -> tokenGenerator.generateAccessTokenWithEmbeddedUserInfo(u, client, scopes))
                .orElse(tokenGenerator.generateAccessToken(client, scopes));

        String sub = user.map(User::getSub).orElse(client.getClientId());
        String unspecifiedUrnHash = user.map(u -> KeyGenerator.oneWayHash(u.getUnspecifiedNameId(), this.salt)).orElse(null);

        AccessToken accessToken = new AccessToken(encryptedAccessToken.getJwtId(), sub, client.getClientId(), scopes,
                encryptedAccessToken.getKeyId(), accessTokenValidity(client), !user.isPresent(),
                authorizationCodeId.orElse(null), unspecifiedUrnHash);
        accessToken = accessTokenRepository.insert(accessToken);

        map.put("access_token", encryptedAccessToken.getValue());
        map.put("token_type", "Bearer");
        if (client.getGrants().contains(GrantType.REFRESH_TOKEN.getValue())) {
            EncryptedTokenValue encryptedRefreshToken = user
                    .map(u -> tokenGenerator.generateRefreshTokenWithEmbeddedUserInfo(u, client))
                    .orElse(tokenGenerator.generateRefreshToken(client));
            String refreshTokenValue = encryptedRefreshToken.getValue();
            refreshTokenRepository.insert(new RefreshToken(encryptedRefreshToken.getJwtId(), accessToken, refreshTokenValidity(client)));
            map.put("refresh_token", refreshTokenValue);
        }
        map.put("expires_in", client.getAccessTokenValidity());
        if (isOpenIDRequest(scopes) && !clientCredentials) {
            TokenValue tokenValue = tokenGenerator.generateIDTokenForTokenEndpoint(user, client, nonce, idTokenClaims, scopes, authorizationTime);
            map.put("id_token", tokenValue.getValue());
        }
        return map;
    }


    private HttpHeaders getResponseHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.CACHE_CONTROL, "no-store");
        headers.set(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType());
        headers.set(HttpHeaders.PRAGMA, "no-cache");
        return headers;
    }

}
