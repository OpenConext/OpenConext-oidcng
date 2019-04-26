package oidc.secure;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import oidc.model.OpenIDClient;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

public class TokenGenerator {

    private static char[] DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            .toCharArray();

    private static Random random = new SecureRandom();

    public static String generateAccessToken() {
        return UUID.randomUUID().toString();
    }

    public static String generateAuthorizationCode() {
        byte[] verifierBytes = new byte[8];
        random.nextBytes(verifierBytes);
        char[] chars = new char[verifierBytes.length];
        for (int i = 0; i < verifierBytes.length; i++) {
            chars[i] = DEFAULT_CODEC[((verifierBytes[i] & 0xFF) % DEFAULT_CODEC.length)];
        }
        return new String(chars);
    }

    public static String idToken(String issuer, String sub, String clientId, Optional<String> nonce,
                                 ResponseType responseType, Optional<String> accessToken) throws JOSEException, ParseException {
        JWSAlgorithm signingAlg = JWSAlgorithm.RS256;

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + (60 * 5 * 1000L)))
                .issuer(issuer)
                .subject(sub)
                .audience(Lists.newArrayList(clientId))
                .jwtID(UUID.randomUUID().toString())
                .claim("kid", "oidc");
        nonce.ifPresent(s -> builder.claim("nonce", s));

        if (AccessTokenHash.isRequiredInIDTokenClaims(responseType)) {
            BearerAccessToken token = accessToken.map(s -> new BearerAccessToken(s))
                    .orElseThrow(() -> new IllegalArgumentException("Access token missing"));
            builder.claim("at_hash", AccessTokenHash.compute(token, signingAlg).getValue());
        }
        JWTClaimsSet claimsSet = builder.build();
//        RSAKey rsaKey = new RSAKeyGenerator(2048).generate();
//        JWKSet jwkSet = JWKSet.parse("");
//        JWK keyByKeyId = jwkSet.getKeyByKeyId("");
//        JWSHeader header = new JWSHeader(signingAlg);
//        SignedJWT signedJWT = new SignedJWT(
//                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
//                claimsSet);
//        signedJWT.sign();
//
//        JWT idToken = new SignedJWT(header, idClaims.build());
//
//        // sign it with the server's key
//        jwtService.signJwt((SignedJWT) idToken);

        return null;//jwtValue.serialize();
    }

    public static Base64URL getAccessTokenHash(JWT jwt) {

        byte[] tokenBytes = jwt.serialize().getBytes();
        MessageDigest hasher = null;
        try {
            hasher = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        hasher.reset();
        hasher.update(tokenBytes);

        byte[] hashBytes = hasher.digest();
        byte[] hashBytesLeftHalf = Arrays.copyOf(hashBytes, hashBytes.length / 2);
        Base64URL encodedHash = Base64URL.encode(hashBytesLeftHalf);

        return encodedHash;
    }

}
