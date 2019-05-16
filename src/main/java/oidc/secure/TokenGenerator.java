package oidc.secure;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadFactory;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import com.nimbusds.openid.connect.sdk.claims.StateHash;
import oidc.endpoints.MapTypeReference;
import oidc.exceptions.InvalidSignatureException;
import oidc.model.OpenIDClient;
import oidc.model.User;
import org.apache.commons.io.IOUtils;
import org.springframework.core.io.Resource;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;

import static java.nio.charset.Charset.defaultCharset;

public class TokenGenerator implements MapTypeReference {

    public static final JWSAlgorithm signingAlg = JWSAlgorithm.RS256;

    private static char[] DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            .toCharArray();

    private Random random = new SecureRandom();

    private String issuer;

    private RSASSASigner signer;

    private RSASSAVerifier verifier;

    private String kid;

    private Map<String, RSAKey> publicKeys;

    private KeysetHandle keysetHandle;

    private String associatedData;

    private ObjectMapper objectMapper;

    private Clock clock;

    public TokenGenerator(Resource jwksKeyStorePath, String issuer, Resource secretKeySetPath, String associatedData,
                          ObjectMapper objectMapper, Clock clock) throws IOException, ParseException, JOSEException, GeneralSecurityException {
        AeadConfig.register();
        JWKSet jwkSet = JWKSet.parse(IOUtils.toString(jwksKeyStorePath.getInputStream(), defaultCharset()));
        RSAKey rsaJWK = (RSAKey) jwkSet.getKeys().get(0);

        this.issuer = issuer;
        this.publicKeys = Collections.singletonMap(kid, rsaJWK.toPublicJWK());
        this.kid = rsaJWK.getKeyID();
        this.signer = new RSASSASigner(rsaJWK);
        this.verifier = new RSASSAVerifier(rsaJWK);
        this.keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(secretKeySetPath.getInputStream()));
        this.associatedData = associatedData;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    public String generateAccessToken() {
        return UUID.randomUUID().toString();
    }

    public String generateRefreshToken() {
        return UUID.randomUUID().toString();
    }

    public String generateAuthorizationCode() {
        byte[] verifierBytes = new byte[12];
        random.nextBytes(verifierBytes);
        char[] chars = new char[verifierBytes.length];
        for (int i = 0; i < verifierBytes.length; i++) {
            chars[i] = DEFAULT_CODEC[((verifierBytes[i] & 0xFF) % DEFAULT_CODEC.length)];
        }
        return new String(chars);
    }

    public String generateAccessTokenWithEmbeddedUserInfo(User user, OpenIDClient client, List<String> scopes) {
        try {
            return doGenerateAccessTokenWithEmbeddedUser(user, client, scopes);
        } catch (Exception e) {
            //anti pattern but too many exceptions to catch without any surviving option
            throw e instanceof RuntimeException ? (RuntimeException) e : new RuntimeException(e);
        }
    }

    private String doGenerateAccessTokenWithEmbeddedUser(User user, OpenIDClient client, List<String> scopes) throws JsonProcessingException, GeneralSecurityException, JOSEException {
        String json = objectMapper.writeValueAsString(user);

        Aead aead = AeadFactory.getPrimitive(keysetHandle);
        byte[] src = aead.encrypt(json.getBytes(defaultCharset()), associatedData.getBytes(defaultCharset()));
        String encryptedClaims = Base64.getEncoder().encodeToString(src);

        Map<String, Object> additionalClaims = new HashMap<>();
        additionalClaims.put("claims", encryptedClaims);
        additionalClaims.put("claim_key_id", kid);

        return idToken(client, Optional.empty(), additionalClaims, Collections.emptyList());
    }

    public User decryptAccessTokenWithEmbeddedUserInfo(String accessToken) {
        try {
            return doDecryptAccessTokenWithEmbeddedUserInfo(accessToken);
        } catch (Exception e) {
            //anti pattern but too many exceptions to catch without any surviving option
            throw e instanceof RuntimeException ? (RuntimeException) e : new RuntimeException(e);
        }
    }

    private User doDecryptAccessTokenWithEmbeddedUserInfo(String accessToken) throws ParseException, JOSEException, GeneralSecurityException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(accessToken);
        Map<String, Object> claims = verifyClaims(signedJWT);
        String encryptedClaims = (String) claims.get("claims");

        Aead aead = AeadFactory.getPrimitive(keysetHandle);
        byte[] decoded = Base64.getDecoder().decode(encryptedClaims);
        String s = new String(aead.decrypt(decoded, associatedData.getBytes(defaultCharset())));

        return objectMapper.readValue(s, User.class);
    }

    public String generateIDTokenForTokenEndpoint(Optional<User> user, OpenIDClient client, List<String> idTokenClaims) throws JOSEException {
        return idToken(client, user, Collections.emptyMap(), idTokenClaims);
    }

    public String generateIDTokenForAuthorizationEndpoint(User user, OpenIDClient client, Nonce nonce,
                                                          ResponseType responseType, String accessToken,
                                                          List<String> claims, Optional<String> authorizationCode,
                                                          State state)
            throws JOSEException {
        Map<String, Object> additionalClaims = new HashMap<>();
        if (nonce != null) {
            additionalClaims.put("nonce", nonce.getValue());
        }
        if (AccessTokenHash.isRequiredInIDTokenClaims(responseType)) {
            additionalClaims.put("at_hash",
                    AccessTokenHash.compute(new BearerAccessToken(accessToken), signingAlg).getValue());
        }
        if (CodeHash.isRequiredInIDTokenClaims(responseType) && authorizationCode.isPresent()) {
            additionalClaims.put("c_hash",
                    CodeHash.compute(new AuthorizationCode(authorizationCode.get()), signingAlg));
        }
        if (state != null && StringUtils.hasText(state.getValue())) {
            additionalClaims.put("s_hash", StateHash.compute(state, signingAlg));
        }
        return idToken(client, Optional.of(user), additionalClaims, claims);
    }

    public Map<String, ? extends JWK> getAllPublicKeys() {
        return this.publicKeys;
    }

    private Map<String, Object> verifyClaims(SignedJWT signedJWT) throws ParseException, JOSEException {
        if (!signedJWT.verify(verifier)) {
            throw new InvalidSignatureException("Tampered JWT");
        }
        return signedJWT.getJWTClaimsSet().getClaims();
    }

    private String idToken(OpenIDClient client, Optional<User> user, Map<String, Object> additionalClaims,
                           List<String> idTokenClaims) throws JOSEException {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .audience(Lists.newArrayList(client.getClientId()))
                .expirationTime(Date.from(clock.instant().plus(client.getAccessTokenValidity(), ChronoUnit.SECONDS)))
                .jwtID(UUID.randomUUID().toString())
                .issuer(issuer)
                .issueTime(Date.from(clock.instant()))
                .subject(user.map(u -> u.getSub()).orElse(client.getClientId()))
                .notBeforeTime(new Date(System.currentTimeMillis()));


        if (!CollectionUtils.isEmpty(idTokenClaims) && user.isPresent()) {
            Map<String, Object> attributes = user.get().getAttributes();
            idTokenClaims.forEach(claim -> {
                if (attributes.containsKey(claim)) {
                    builder.claim(claim, attributes.get(claim));
                }
            });
        }
        additionalClaims.forEach((name, value) -> builder.claim(name, value));

        JWTClaimsSet claimsSet = builder.build();
        JWSHeader header = new JWSHeader.Builder(signingAlg).type(JOSEObjectType.JWT).keyID(kid).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(this.signer);
        return signedJWT.serialize();
    }

}
