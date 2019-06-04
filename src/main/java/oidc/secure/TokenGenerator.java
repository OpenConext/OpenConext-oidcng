package oidc.secure;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadFactory;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
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
import oidc.model.SigningKey;
import oidc.model.SymmetricKey;
import oidc.model.User;
import oidc.repository.SequenceRepository;
import oidc.repository.SigningKeyRepository;
import oidc.repository.SymmetricKeyRepository;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.nio.charset.Charset.defaultCharset;
import static java.util.stream.Collectors.toMap;

@Component
public class TokenGenerator implements MapTypeReference, ApplicationListener<ApplicationStartedEvent> {

    public static final JWSAlgorithm signingAlg = JWSAlgorithm.RS256;
    public static final Instant instant = Instant.parse("2100-01-01T00:00:00.00Z");

    private static char[] DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            .toCharArray();

    private Random random = new SecureRandom();

    private String issuer;

    private Map<String, JWSSigner> signers;

    private Map<String, JWSVerifier> verifiers;

    private String currentSigningKeyId;

    private List<RSAKey> publicKeys;

    private byte[] associatedData;

    private KeysetHandle primaryKeysetHandle;

    private Map<String, KeysetHandle> keysetHandleMap;

    private String currentSymmetricKeyId;

    private ObjectMapper objectMapper;

    private Clock clock;

    private SigningKeyRepository signingKeyRepository;

    private SymmetricKeyRepository symmetricKeyRepository;

    private SequenceRepository sequenceRepository;

    @Autowired
    public TokenGenerator(@Value("${spring.security.saml2.service-provider.entity-id}") String issuer,
                          @Value("${secret_key_set_path}") Resource secretKeySetPath,
                          @Value("${associated_data}") String associatedData,
                          ObjectMapper objectMapper,
                          SigningKeyRepository signingKeyRepository,
                          SequenceRepository sequenceRepository,
                          SymmetricKeyRepository symmetricKeyRepository,
                          Environment environment) throws IOException, GeneralSecurityException {
        Security.addProvider(new BouncyCastleProvider());
        AeadConfig.register();

        this.signingKeyRepository = signingKeyRepository;
        this.sequenceRepository = sequenceRepository;
        this.symmetricKeyRepository = symmetricKeyRepository;
        this.issuer = issuer;

        this.objectMapper = objectMapper;
        this.clock = environment.acceptsProfiles(Profiles.of("dev")) ? Clock.fixed(instant, ZoneId.systemDefault()) : Clock.systemDefaultZone();

        this.primaryKeysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(secretKeySetPath.getInputStream()));
        this.associatedData = associatedData.getBytes(defaultCharset());

    }

    @Override
    public void onApplicationEvent(ApplicationStartedEvent event) {
        //we need to run this after any possible mongo migrations
        try {
            initializeSymmetricKeys();
            initializeSigningKeys();
        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private void initializeSigningKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
        List<RSAKey> rsaKeys = this.signingKeyRepository.findAllByOrderByCreatedDesc().stream()
                .filter(signingKey -> StringUtils.hasText(signingKey.getSymmetricKeyId()))
                .map(this::parseEncryptedRsaKey)
                .collect(Collectors.toList());

        if (rsaKeys.isEmpty()) {
            SigningKey signingKey = this.generateEncryptedRsaKey();
            this.signingKeyRepository.save(signingKey);
            RSAKey rsaKey = this.parseEncryptedRsaKey(signingKey);
            rsaKeys = Collections.singletonList(rsaKey);
        }

        this.publicKeys = rsaKeys.stream().map(RSAKey::toPublicJWK).collect(Collectors.toList());
        this.currentSigningKeyId = rsaKeys.get(0).getKeyID();
        this.signers = rsaKeys.stream().collect(toMap(JWK::getKeyID, this::createRSASigner));
        this.verifiers = rsaKeys.stream().collect(toMap(JWK::getKeyID, this::createRSAVerifier));
    }

    public SigningKey rolloverSigningKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
        SigningKey signingKey = this.generateEncryptedRsaKey();
        this.signingKeyRepository.save(signingKey);
        this.initializeSigningKeys();
        return signingKey;
    }

    private void initializeSymmetricKeys() {
        List<KeysetHandle> keysetHandles = this.symmetricKeyRepository.findAllByOrderByCreatedDesc().stream()
                .map(symmetricKey -> this.parseKeysetHandle(symmetricKey))
                .collect(Collectors.toList());

        if (keysetHandles.isEmpty()) {
            signingKeyRepository.deleteAll();
            SymmetricKey symmetricKey = generateSymmetricKey();
            keysetHandles = Collections.singletonList(parseKeysetHandle(symmetricKey));
        }
        this.currentSymmetricKeyId = String.valueOf(keysetHandles.get(0).getKeysetInfo().getPrimaryKeyId());
        this.keysetHandleMap = keysetHandles.stream().collect(toMap(
                keysetHandle -> String.valueOf(keysetHandle.getKeysetInfo().getPrimaryKeyId()),
                keysetHandle -> keysetHandle));
    }

    private SymmetricKey generateSymmetricKey() {
        try {
            KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_CTR_HMAC_SHA256);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            keysetHandle.write(JsonKeysetWriter.withOutputStream(outputStream), AeadFactory.getPrimitive(primaryKeysetHandle));
            int primaryKeyId = keysetHandle.getKeysetInfo().getPrimaryKeyId();
            sequenceRepository.updateSymmetricKeyId(Long.valueOf(primaryKeyId));
            String aead = Base64.getEncoder().encodeToString(outputStream.toString().getBytes(defaultCharset()));
            String keyId = String.valueOf(primaryKeyId);
            SymmetricKey symmetricKey = new SymmetricKey(keyId, aead, new Date());
            symmetricKeyRepository.save(symmetricKey);
            return symmetricKey;
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public SymmetricKey rolloverSymmetricKeys() {
        SymmetricKey symmetricKey = generateSymmetricKey();
        this.initializeSymmetricKeys();
        return symmetricKey;
    }

    private RSAKey parseEncryptedRsaKey(SigningKey signingKey) {
        try {
            return RSAKey.parse(decryptAead(signingKey.getJwk(), signingKey.getSymmetricKeyId()));
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private KeysetHandle parseKeysetHandle(SymmetricKey symmetricKey) {
        byte[] decoded = Base64.getDecoder().decode(symmetricKey.getAead());
        try {
            return KeysetHandle.read(JsonKeysetReader.withBytes(decoded), AeadFactory.getPrimitive(primaryKeysetHandle));
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
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

    public String generateAccessTokenWithEmbeddedUserInfo(User user, OpenIDClient client) {
        try {
            String signingKey = ensureLatestSigningKey();
            return doGenerateAccessTokenWithEmbeddedUser(user, client, signingKey);
        } catch (Exception e) {
            //anti pattern but too many exceptions to catch without any surviving option
            throw e instanceof RuntimeException ? (RuntimeException) e : new RuntimeException(e);
        }
    }

    private String doGenerateAccessTokenWithEmbeddedUser(User user, OpenIDClient client, String signingKey) throws JsonProcessingException, GeneralSecurityException, JOSEException {
        String json = objectMapper.writeValueAsString(user);

        String encryptedClaims = encryptAead(json);

        Map<String, Object> additionalClaims = new HashMap<>();
        additionalClaims.put("claims", encryptedClaims);
        additionalClaims.put("claim_key_id", currentSymmetricKeyId);

        return idToken(client, Optional.empty(), additionalClaims, Collections.emptyList(), true, signingKey);
    }

    private String encryptAead(String s) {
        try {
            KeysetHandle keysetHandle = this.safeGet(this.ensureLatestSymmetricKey(), this.keysetHandleMap);
            Aead aead = AeadFactory.getPrimitive(keysetHandle);
            byte[] src = aead.encrypt(s.getBytes(defaultCharset()), associatedData);
            return Base64.getEncoder().encodeToString(src);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
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
        String keyId = (String) claims.get("claim_key_id");

        String s = decryptAead(encryptedClaims, keyId);

        return objectMapper.readValue(s, User.class);
    }

    private String decryptAead(String s, String symmetricKeyId) {
        try {
            this.ensureLatestSymmetricKey();
            KeysetHandle keysetHandle = safeGet(symmetricKeyId, this.keysetHandleMap);
            Aead aead = AeadFactory.getPrimitive(keysetHandle);
            byte[] decoded = Base64.getDecoder().decode(s);
            return new String(aead.decrypt(decoded, associatedData));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public String generateIDTokenForTokenEndpoint(Optional<User> user, OpenIDClient client, String nonce, List<String> idTokenClaims) throws JOSEException, NoSuchProviderException, NoSuchAlgorithmException {
        Map<String, Object> additionalClaims = StringUtils.hasText(nonce) ? Collections.singletonMap("nonce", nonce) : Collections.emptyMap();
        String signingKey = ensureLatestSigningKey();
        return idToken(client, user, additionalClaims, idTokenClaims, false, signingKey);
    }

    public String generateIDTokenForAuthorizationEndpoint(User user, OpenIDClient client, Nonce nonce,
                                                          ResponseType responseType, String accessToken,
                                                          List<String> claims, Optional<String> authorizationCode,
                                                          State state)
            throws JOSEException, NoSuchProviderException, NoSuchAlgorithmException {
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
        String signingKey = ensureLatestSigningKey();
        return idToken(client, Optional.of(user), additionalClaims, claims, false, signingKey);
    }

    public List<JWK> getAllPublicKeys() {
        return new ArrayList<>(this.publicKeys);
    }

    private RSAKey generateRsaKey(String keyID) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .algorithm(signingAlg)
                .keyID(keyID)
                .build();
    }

    private SigningKey generateEncryptedRsaKey() throws NoSuchProviderException, NoSuchAlgorithmException {
        Long increment = this.sequenceRepository.incrementSigningKeyId();
        RSAKey rsaKey = generateRsaKey(signingKeyFormat(increment));
        String encryptedKey = encryptAead(rsaKey.toJSONString());
        return new SigningKey(rsaKey.getKeyID(), currentSymmetricKeyId, encryptedKey, new Date());
    }

    private String signingKeyFormat(Long increment) {
        return String.format("key_%s", increment);
    }

    private String symmetricKeyFormat(Long nbr) {
        return nbr != null ? Integer.toString(nbr.intValue()) : "0";
    }

    private Map<String, Object> verifyClaims(SignedJWT signedJWT) throws ParseException, JOSEException {
        String keyID = signedJWT.getHeader().getKeyID();
        JWSVerifier verifier = this.safeGet(keyID, verifiers);
        if (!signedJWT.verify(verifier)) {
            throw new InvalidSignatureException("Tampered JWT");
        }
        return signedJWT.getJWTClaimsSet().getClaims();
    }

    private String idToken(OpenIDClient client, Optional<User> user, Map<String, Object> additionalClaims,
                           List<String> idTokenClaims, boolean includeAllowedResourceServers, String signingKey) throws JOSEException {
        List<String> audiences = new ArrayList<>();
        audiences.add(client.getClientId());
        if (includeAllowedResourceServers) {
            audiences.addAll(client.getAllowedResourceServers().stream()
                    .filter(rsEntityId -> !client.getClientId().equals(rsEntityId))
                    .collect(Collectors.toList()));
        }
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .audience(audiences)
                .expirationTime(Date.from(clock.instant().plus(client.getAccessTokenValidity(), ChronoUnit.SECONDS)))
                .jwtID(UUID.randomUUID().toString())
                .issuer(issuer)
                .issueTime(Date.from(clock.instant()))
                .subject(user.map(User::getSub).orElse(client.getClientId()))
                .notBeforeTime(new Date(System.currentTimeMillis()));


        if (!CollectionUtils.isEmpty(idTokenClaims) && user.isPresent()) {
            Map<String, Object> attributes = user.get().getAttributes();
            idTokenClaims.forEach(claim -> {
                if (attributes.containsKey(claim)) {
                    builder.claim(claim, attributes.get(claim));
                }
            });
        }
        additionalClaims.forEach(builder::claim);

        JWTClaimsSet claimsSet = builder.build();
        JWSHeader header = new JWSHeader.Builder(signingAlg).type(JOSEObjectType.JWT).keyID(signingKey).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        JWSSigner jswsSigner = this.safeGet(signingKey, signers);
        signedJWT.sign(jswsSigner);
        return signedJWT.serialize();
    }

    private String ensureLatestSigningKey() throws NoSuchProviderException, NoSuchAlgorithmException {
        if (!signingKeyFormat(sequenceRepository.currentSigningKeyId()).equals(this.currentSigningKeyId)) {
            this.initializeSigningKeys();
        }
        return this.currentSigningKeyId;
    }

    private String ensureLatestSymmetricKey() throws NoSuchAlgorithmException {
        if (!symmetricKeyFormat(sequenceRepository.currentSymmetricKeyId()).equals(this.currentSymmetricKeyId)) {
            this.initializeSymmetricKeys();
        }
        return this.currentSymmetricKeyId;
    }

    private RSASSASigner createRSASigner(RSAKey k) {
        try {
            return new RSASSASigner(k);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private RSASSAVerifier createRSAVerifier(RSAKey k) {
        try {
            return new RSASSAVerifier(k);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private <T> T safeGet(String k, Map<String, T> map) {
        T t = map.get(k);
        if (t == null) {
            throw new IllegalArgumentException(String.format("Map with keys %s does not contain key %s", map.keySet(), k));
        }
        return t;
    }

    public String getCurrentSigningKeyId() {
        return this.currentSigningKeyId;
    }

    public String getCurrentSymmetricKeyId() {
        return currentSymmetricKeyId;
    }
}
