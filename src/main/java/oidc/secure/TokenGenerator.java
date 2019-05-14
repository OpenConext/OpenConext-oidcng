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
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.impl.RSACryptoProvider;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import oidc.endpoints.MapTypeReference;
import oidc.exceptions.InvalidSignatureException;
import oidc.model.OpenIDClient;
import oidc.model.User;
import org.apache.commons.io.IOUtils;
import org.springframework.core.io.Resource;
import org.springframework.util.CollectionUtils;

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

    private static char[] DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            .toCharArray();

    private Random random = new SecureRandom();

    private String issuer;

    private RSASSASigner signer;

    private RSASSAVerifier verifier;

    private String kid;

    private Map<String, RSAKey> publicKeys;

    private JWSAlgorithm signingAlg = JWSAlgorithm.RS256;

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
            throw new RuntimeException(e);
        }
    }

    private String doGenerateAccessTokenWithEmbeddedUser(User user, OpenIDClient client, List<String> scopes) throws JsonProcessingException, GeneralSecurityException, JOSEException {
        Map<String, Object> result = new HashMap<>();
        result.put("user", user);
        result.put("scope", String.join(",", scopes));
        result.put("client_id", client.getClientId());
        result.put("exp", (this.clock.millis() / 1000L) + client.getAccessTokenValidity());
        String json = objectMapper.writeValueAsString(result);

        Aead aead = AeadFactory.getPrimitive(keysetHandle);
        byte[] src = aead.encrypt(json.getBytes(defaultCharset()), associatedData.getBytes(defaultCharset()));
        String encryptedClaims = Base64.getEncoder().encodeToString(src);

        Map<String, Object> additionalClaims = new HashMap<>();
        additionalClaims.put("claims", encryptedClaims);
        additionalClaims.put("claim_key_id", kid);

        return idToken(client, Optional.empty(), additionalClaims, Collections.emptyList());
    }

    public Map<String, Object> decryptAccessTokenWithEmbeddedUserInfo(String accessToken) {
        try {
            return doDecryptAccessTokenWithEmbeddedUserInfo(accessToken);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Map<String, Object> doDecryptAccessTokenWithEmbeddedUserInfo(String accessToken) throws ParseException, JOSEException, GeneralSecurityException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(accessToken);
        Map<String, Object> claims = verifyClaims(signedJWT);
        String encryptedClaims = (String) claims.get("claims");

        Aead aead = AeadFactory.getPrimitive(keysetHandle);
        byte[] decoded = Base64.getDecoder().decode(encryptedClaims);
        String s = new String(aead.decrypt(decoded, associatedData.getBytes(defaultCharset())));

        Map<String, Object> map = objectMapper.readValue(s, mapTypeReference);
        map.put("user", objectMapper.convertValue(map.get("user"), User.class));
        return map;
    }

    public String generateIDTokenForTokenEndpoint(Optional<User> user, OpenIDClient client, List<String> idTokenClaims) throws JOSEException {
        return idToken(client, user, new HashMap<>(), idTokenClaims);
    }

    public String generateIDTokenForAuthorizationEndpoint(User user, OpenIDClient client, Nonce nonce,
                                                          ResponseType responseType, String accessToken,
                                                          List<String> claims) throws JOSEException {
        Map<String, Object> additionalClaims = new HashMap<>();
        if (nonce != null) {
            additionalClaims.put("nonce", nonce.getValue());
        }
        if (AccessTokenHash.isRequiredInIDTokenClaims(responseType)) {
            additionalClaims.put("at_hash",
                    AccessTokenHash.compute(new BearerAccessToken(accessToken), signingAlg).getValue());
        }
        return idToken(client, Optional.of(user), additionalClaims, claims);
    }

    private void addClaimsRequested(User user, List<String> claims, Map<String, Object> additionalClaims) {
        if (!CollectionUtils.isEmpty(claims)) {
            Map<String, Object> attributes = user.getAttributes();
            claims.forEach(claim -> {
                if (attributes.containsKey(claim)) {
                    additionalClaims.put(claim, attributes.get(claim));
                }
            });
        }
    }

    private Map<String, Object> verifyClaims(SignedJWT signedJWT) throws ParseException, JOSEException {
        if (!signedJWT.verify(verifier)) {
            throw new InvalidSignatureException("Tampered JWT");
        }
        return signedJWT.getJWTClaimsSet().getClaims();
    }

    private Map<String, Object> doDecryptAccessToken(String jweString, JWEDecrypter decrypter) throws ParseException, JOSEException {
        JWEObject jweObject = JWEObject.parse(jweString);
        jweObject.decrypt(decrypter);
        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
        return verifyClaims(signedJWT);
    }

    private String encryptedAccessToken(Map<String, Object> input, JWEEncrypter encrypter) throws JOSEException {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        input.forEach((name, value) -> builder.claim(name, value));

        SignedJWT signedJWT = getSignedJWT(builder);
        JWEHeader header = encrypter instanceof RSACryptoProvider ?
                new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM) :
                new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512);

        JWEObject jweObject = new JWEObject(header, new Payload(signedJWT));
        jweObject.encrypt(encrypter);
        return jweObject.serialize();
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

        user.ifPresent(u -> addClaimsRequested(u, idTokenClaims, additionalClaims));
        additionalClaims.forEach((name, value) -> builder.claim(name, value));

        SignedJWT signedJWT = getSignedJWT(builder);
        return signedJWT.serialize();
    }

    private SignedJWT getSignedJWT(JWTClaimsSet.Builder builder) throws JOSEException {
        JWTClaimsSet claimsSet = builder.build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).keyID(kid).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(this.signer);
        return signedJWT;
    }

    public Map<String, ? extends JWK> getAllPublicKeys() {
        return this.publicKeys;
    }
}
