package oidc.secure;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesCtrHmacAeadKeyManager;
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
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import com.nimbusds.openid.connect.sdk.claims.StateHash;
import lombok.SneakyThrows;
import oidc.endpoints.MapTypeReference;
import oidc.model.EncryptedTokenValue;
import oidc.model.OpenIDClient;
import oidc.model.SigningKey;
import oidc.model.SymmetricKey;
import oidc.model.TokenValue;
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
import java.text.SimpleDateFormat;
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
@SuppressWarnings("unchecked")
public class TokenGenerator implements MapTypeReference, ApplicationListener<ApplicationStartedEvent> {

    public static final JWSAlgorithm signingAlg = JWSAlgorithm.RS256;
    public static final Instant instant = Instant.parse("2100-01-01T00:00:00.00Z");

    private static final char[] DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            .toCharArray();

    private final Random random = new SecureRandom();

    private final String issuer;

    private Map<String, JWSSigner> signers;

    private Map<String, JWSVerifier> verifiers;

    private String currentSigningKeyId;

    private List<RSAKey> publicKeys;

    private final byte[] associatedData;

    private final KeysetHandle primaryKeysetHandle;

    private Map<String, KeysetHandle> keysetHandleMap;

    private String currentSymmetricKeyId;

    private final ObjectMapper objectMapper;

    private final Clock clock;

    private final SigningKeyRepository signingKeyRepository;

    private final SymmetricKeyRepository symmetricKeyRepository;

    private final SequenceRepository sequenceRepository;

    private final String defaultAcrValue;

    @Autowired
    public TokenGenerator(@Value("${sp.entity_id}") String issuer,
                          @Value("${secret_key_set_path}") Resource secretKeySetPath,
                          @Value("${associated_data}") String associatedData,
                          @Value("${openid_configuration_path}") Resource configurationPath,
                          @Value("${default_acr_value}") String defaultAcrValue,
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

        Map<String, Object> wellKnownConfiguration = objectMapper.readValue(configurationPath.getInputStream(), mapTypeReference);
        this.defaultAcrValue = defaultAcrValue;

    }

    @SneakyThrows
    @Override
    public void onApplicationEvent(ApplicationStartedEvent event) {
        //we need to run this after any possible mongo migrations
        initializeSymmetricKeys();
        initializeSigningKeys();
    }

    private void initializeSigningKeys() throws GeneralSecurityException, ParseException, IOException {
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

    public SigningKey rolloverSigningKeys() throws GeneralSecurityException, ParseException, IOException {
        SigningKey signingKey = this.generateEncryptedRsaKey();
        this.signingKeyRepository.save(signingKey);
        this.initializeSigningKeys();
        return signingKey;
    }

    private void initializeSymmetricKeys() throws GeneralSecurityException, IOException {
        List<KeysetHandle> keysetHandles = this.symmetricKeyRepository.findAllByOrderByCreatedDesc().stream()
                .map(this::parseKeysetHandle)
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

    private SymmetricKey generateSymmetricKey() throws GeneralSecurityException, IOException {
        KeyTemplate keyTemplate = AesCtrHmacAeadKeyManager.aes256CtrHmacSha256Template();
        KeysetHandle keysetHandle = KeysetHandle.generateNew(keyTemplate);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        Aead primitive = primaryKeysetHandle.getPrimitive(Aead.class);
        keysetHandle.write(JsonKeysetWriter.withOutputStream(outputStream), primitive);
        int primaryKeyId = keysetHandle.getKeysetInfo().getPrimaryKeyId();
        String newKeyId = String.valueOf(primaryKeyId);
        sequenceRepository.updateSymmetricKeyId(newKeyId);
        String aead = Base64.getEncoder().encodeToString(outputStream.toString().getBytes(defaultCharset()));
        String keyId = newKeyId;
        SymmetricKey symmetricKey = new SymmetricKey(keyId, aead, new Date());
        symmetricKeyRepository.save(symmetricKey);
        return symmetricKey;
    }

    public SymmetricKey rolloverSymmetricKeys() throws GeneralSecurityException, IOException {
        SymmetricKey symmetricKey = generateSymmetricKey();
        this.initializeSymmetricKeys();
        return symmetricKey;
    }

    @SneakyThrows
    private RSAKey parseEncryptedRsaKey(SigningKey signingKey) {
        return RSAKey.parse(decryptAead(signingKey.getJwk(), signingKey.getSymmetricKeyId()));
    }

    @SneakyThrows
    private KeysetHandle parseKeysetHandle(SymmetricKey symmetricKey) {
        byte[] decoded = Base64.getDecoder().decode(symmetricKey.getAead());
        Aead primitive = primaryKeysetHandle.getPrimitive(Aead.class);
        return KeysetHandle.read(JsonKeysetReader.withBytes(decoded), primitive);
    }

    @SneakyThrows
    public EncryptedTokenValue generateAccessToken(OpenIDClient client) {
        String currentSigningKeyId = ensureLatestSigningKey();
        TokenValue tokenValue = idToken(client, Optional.empty(), Collections.emptyMap(), Collections.emptyList(),
                false, currentSigningKeyId, true);
        return new EncryptedTokenValue(tokenValue, currentSigningKeyId);
    }

    @SneakyThrows
    public EncryptedTokenValue generateRefreshToken(OpenIDClient client) {
        String currentSigningKeyId = ensureLatestSigningKey();
        TokenValue tokenValue = idToken(client, Optional.empty(), Collections.emptyMap(), Collections.emptyList(),
                false, currentSigningKeyId, false);
        return new EncryptedTokenValue(tokenValue, currentSigningKeyId);
    }

    public String generateAuthorizationCode() {
        byte[] verifierBytes = new byte[12];
        random.nextBytes(verifierBytes);
        char[] chars = new char[verifierBytes.length];
        for (int i = 0; i < verifierBytes.length; i++) {
            chars[i] = DEFAULT_CODEC[random.nextInt(DEFAULT_CODEC.length)];
        }
        return new String(chars);
    }

    @SneakyThrows
    public EncryptedTokenValue generateAccessTokenWithEmbeddedUserInfo(User user, OpenIDClient client) {
        String currentSigningKeyId = this.ensureLatestSigningKey();
        TokenValue tokenValue = doGenerateAccessTokenWithEmbeddedUser(user, client, currentSigningKeyId, true);
        return new EncryptedTokenValue(tokenValue, currentSigningKeyId);
    }

    @SneakyThrows
    public EncryptedTokenValue generateRefreshTokenWithEmbeddedUserInfo(User user, OpenIDClient client) {
        String currentSigningKeyId = this.ensureLatestSigningKey();
        return new EncryptedTokenValue(doGenerateAccessTokenWithEmbeddedUser(user, client, currentSigningKeyId, false), currentSigningKeyId);
    }

    private TokenValue doGenerateAccessTokenWithEmbeddedUser(User user, OpenIDClient client, String signingKey, boolean isAccessToken)
            throws IOException, JOSEException, GeneralSecurityException, ParseException {
        String json = objectMapper.writeValueAsString(user);
        String currentSymmetricKeyId = this.ensureLatestSymmetricKey();
        String value = encryptAead(json, currentSymmetricKeyId);

        Map<String, Object> additionalClaims = new HashMap<>();
        additionalClaims.put("claims", value);
        additionalClaims.put("claim_key_id", currentSymmetricKeyId);

        return idToken(client, Optional.empty(), additionalClaims, Collections.emptyList(),
                true, signingKey, isAccessToken);
    }

    private String encryptAead(String s, String currentSymmetricKeyId) throws GeneralSecurityException, IOException {
        KeysetHandle keysetHandle = this.safeGet(currentSymmetricKeyId, this.keysetHandleMap);
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        byte[] src = aead.encrypt(s.getBytes(defaultCharset()), associatedData);
        return Base64.getEncoder().encodeToString(src);
    }

    public Optional<SignedJWT> parseAndValidateSignedJWT(String accessToken) {
        try {
            return Optional.of(SignedJWT.parse(accessToken));
        } catch (ParseException e) {
            return Optional.empty();
        }
    }

    @SneakyThrows
    public User decryptAccessTokenWithEmbeddedUserInfo(SignedJWT signedJWT) {
        return doDecryptAccessTokenWithEmbeddedUserInfo(signedJWT);
    }

    private User doDecryptAccessTokenWithEmbeddedUserInfo(SignedJWT signedJWT) throws ParseException, JOSEException, IOException, GeneralSecurityException {
        Map<String, Object> claims = verifyClaims(signedJWT);
        String encryptedClaims = (String) claims.get("claims");
        String keyId = (String) claims.get("claim_key_id");

        String s = decryptAead(encryptedClaims, keyId);

        return objectMapper.readValue(s, User.class);
    }

    private String decryptAead(String s, String symmetricKeyId) throws GeneralSecurityException, IOException {
        this.ensureLatestSymmetricKey();
        KeysetHandle keysetHandle = safeGet(symmetricKeyId, this.keysetHandleMap);
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        byte[] decoded = Base64.getDecoder().decode(s);
        return new String(aead.decrypt(decoded, associatedData));
    }

    @SneakyThrows
    public TokenValue generateIDTokenForTokenEndpoint(Optional<User> user, OpenIDClient client, String nonce, List<String> idTokenClaims,
                                                      Optional<Long> authorizationTime) {
        Map<String, Object> additionalClaims = new HashMap<>();
        authorizationTime.ifPresent(time -> additionalClaims.put("auth_time", time));
        if (StringUtils.hasText(nonce)) {
            additionalClaims.put("nonce", nonce);
        }
        String currentSigningKeyId = ensureLatestSigningKey();
        return idToken(client, user, additionalClaims, idTokenClaims, false, currentSigningKeyId, true);
    }

    @SneakyThrows
    public TokenValue generateIDTokenForAuthorizationEndpoint(User user, OpenIDClient client, Nonce nonce,
                                                              ResponseType responseType, String accessToken,
                                                              List<String> claims, Optional<String> authorizationCode,
                                                              State state) {
        Map<String, Object> additionalClaims = new HashMap<>();
        additionalClaims.put("auth_time", System.currentTimeMillis() / 1000L);
        if (nonce != null) {
            additionalClaims.put("nonce", nonce.getValue());
        }
        if (AccessTokenHash.isRequiredInIDTokenClaims(responseType)) {
            additionalClaims.put("at_hash",
                    AccessTokenHash.compute(new BearerAccessToken(accessToken), signingAlg).getValue());
        }
        if (CodeHash.isRequiredInIDTokenClaims(responseType) && authorizationCode.isPresent()) {
            additionalClaims.put("c_hash",
                    CodeHash.compute(new com.nimbusds.oauth2.sdk.AuthorizationCode(authorizationCode.get()), signingAlg));
        }
        if (state != null && StringUtils.hasText(state.getValue())) {
            additionalClaims.put("s_hash", StateHash.compute(state, signingAlg));
        }
        String currentSigningKeyId = ensureLatestSigningKey();
        return idToken(client, Optional.of(user), additionalClaims, claims, false,
                currentSigningKeyId, true);
    }

    public List<JWK> getAllPublicKeys() throws GeneralSecurityException, ParseException, IOException {
        this.ensureLatestSigningKey();
        return new ArrayList<>(this.publicKeys);
    }

    private RSAKey generateRsaKey(String keyID) throws NoSuchProviderException, NoSuchAlgorithmException {
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

    private SigningKey generateEncryptedRsaKey() throws GeneralSecurityException, IOException {
        String keyId = new SimpleDateFormat("yyyy_MM_dd_HH_mm_ss_SSS").format(new Date());
        this.sequenceRepository.updateSigningKeyId(keyId);
        RSAKey rsaKey = generateRsaKey(String.format("key_%s", keyId));
        String currentSymmetricKeyId = this.ensureLatestSymmetricKey();
        String value = encryptAead(rsaKey.toJSONString(), currentSymmetricKeyId);
        return new SigningKey(rsaKey.getKeyID(), currentSymmetricKeyId, value, new Date());
    }

    private Map<String, Object> verifyClaims(SignedJWT signedJWT) throws ParseException, JOSEException, GeneralSecurityException, IOException {
        String keyID = signedJWT.getHeader().getKeyID();
        this.ensureLatestSigningKey();
        JWSVerifier verifier = this.safeGet(keyID, this.verifiers);
        if (!signedJWT.verify(verifier)) {
            throw new JOSEException("Tampered JWT");
        }
        return signedJWT.getJWTClaimsSet().getClaims();
    }

    private TokenValue idToken(OpenIDClient client, Optional<User> optionalUser, Map<String, Object> additionalClaims,
                               List<String> idTokenClaims, boolean includeAllowedResourceServers, String signingKey,
                               boolean isAccessToken) throws JOSEException, GeneralSecurityException, ParseException, IOException {
        List<String> audiences = new ArrayList<>();
        audiences.add(client.getClientId());
        if (includeAllowedResourceServers && isAccessToken) {
            audiences.addAll(client.getAllowedResourceServers().stream()
                    .filter(rsEntityId -> !client.getClientId().equals(rsEntityId))
                    .collect(Collectors.toList()));
        }
        int tokenValidity = isAccessToken ? client.getAccessTokenValidity() : client.getRefreshTokenValidity();
        String jti = UUID.randomUUID().toString();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .audience(audiences)
                .expirationTime(Date.from(clock.instant().plus(tokenValidity, ChronoUnit.SECONDS)))
                .jwtID(jti)
                .issuer(issuer)
                .issueTime(Date.from(clock.instant()))
                .subject(optionalUser.map(User::getSub).orElse(client.getClientId()))
                .notBeforeTime(new Date(System.currentTimeMillis()));


        if (!CollectionUtils.isEmpty(idTokenClaims) && optionalUser.isPresent() && isAccessToken) {
            User user = optionalUser.get();
            Map<String, Object> attributes = user.getAttributes();
            idTokenClaims.forEach(claim -> {
                if (attributes.containsKey(claim)) {
                    builder.claim(claim, attributes.get(claim));
                }
            });
        }
        optionalUser.ifPresent(user -> {
            List<String> acrClaims = user.getAcrClaims();
            if (CollectionUtils.isEmpty(acrClaims)) {
                builder.claim("acr", defaultAcrValue);
            } else {
                builder.claim("acr", String.join(" ", acrClaims));
            }
        });

        additionalClaims.forEach(builder::claim);

        JWTClaimsSet claimsSet = builder.build();
        JWSHeader header = new JWSHeader.Builder(signingAlg).type(JOSEObjectType.JWT).keyID(signingKey).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        this.ensureLatestSigningKey();
        JWSSigner jswsSigner = this.safeGet(signingKey, this.signers);
        signedJWT.sign(jswsSigner);
        return new TokenValue(signedJWT.serialize(), jti);
    }

    private String ensureLatestSigningKey() throws GeneralSecurityException, ParseException, IOException {
        if (!sequenceRepository.currentSigningKeyId().equals(this.currentSigningKeyId)) {
            this.initializeSigningKeys();
        }
        return this.currentSigningKeyId;
    }

    private String ensureLatestSymmetricKey() throws GeneralSecurityException, IOException {
        if (!sequenceRepository.currentSymmetricKeyId().equals(this.currentSymmetricKeyId)) {
            this.initializeSymmetricKeys();
        }
        return this.currentSymmetricKeyId;
    }

    @SneakyThrows
    private RSASSASigner createRSASigner(RSAKey k) {
        return new RSASSASigner(k);
    }

    @SneakyThrows
    private RSASSAVerifier createRSAVerifier(RSAKey k) {
        return new RSASSAVerifier(k);
    }

    private <T> T safeGet(String k, Map<String, T> map) {
        T t = map.get(k);
        if (t == null) {
            throw new IllegalArgumentException(String.format("Map with keys %s does not contain key %s", map.keySet(), k));
        }
        return t;
    }

}
