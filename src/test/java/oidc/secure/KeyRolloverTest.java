package oidc.secure;

import oidc.AbstractIntegrationTest;
import oidc.SeedUtils;
import oidc.model.AccessToken;
import oidc.model.SigningKey;
import oidc.model.SymmetricKey;
import org.junit.Test;
import org.springframework.data.mongodb.core.BulkOperations;
import org.springframework.data.mongodb.core.query.Query;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.IntStream;

import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertEquals;

public class KeyRolloverTest extends AbstractIntegrationTest implements SeedUtils {

    @Test
    public void rolloverSigningKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
        resetAndCreateSigningKeys(3);
        final List<String> signingKeys = mongoTemplate.findAll(SigningKey.class).stream().map(SigningKey::getKeyId).sorted().collect(toList());
        assertEquals(3, signingKeys.size());

        List<AccessToken> tokens = IntStream.rangeClosed(0, 10).mapToObj(i -> accessToken("val" + i, signingKeys.get(i % 2))).collect(toList());
        mongoTemplate.bulkOps(BulkOperations.BulkMode.ORDERED, AccessToken.class)
                .remove(new Query())
                .insert(tokens)
                .execute();

        KeyRollover keyRollover = new KeyRollover(tokenGenerator, mongoTemplate, true);
        keyRollover.rollover();

        List<String> keys = mongoTemplate.findAll(SigningKey.class).stream().map(SigningKey::getKeyId).sorted().collect(toList());
        //would expect 4, but one signing key is cleaned up as it is not used in
        assertEquals(3, keys.size());
    }

    @Test
    public void cronJobResponsible() {
        KeyRollover keyRollover = new KeyRollover(null, null, false);
        keyRollover.rollover();
    }

    @Test
    public void rolloverSymmetricKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
        resetAndCreateSymmetricKeys(3);
        List<SymmetricKey> symmetricKeys = mongoTemplate.findAll(SymmetricKey.class);
        assertEquals(3, symmetricKeys.size());

        List<SigningKey> signingKeys = IntStream.rangeClosed(0, 5).mapToObj(i ->
                new SigningKey("key_" + i, symmetricKeys.get(0).getKeyId(), "jwk", new Date())).collect(toList());
        mongoTemplate.bulkOps(BulkOperations.BulkMode.ORDERED, SigningKey.class)
                .remove(new Query())
                .insert(signingKeys)
                .execute();

        KeyRollover keyRollover = new KeyRollover(tokenGenerator, mongoTemplate, true);
        keyRollover.doSymmetricKeyRollover();

        List<String> keyIds = mongoTemplate.findAll(SymmetricKey.class).stream()
                .map(SymmetricKey::getKeyId)
                .sorted()
                .collect(toList());

        assertEquals(
                Arrays.asList(symmetricKeys.get(0).getKeyId(), tokenGenerator.getCurrentSymmetricKeyId()).stream().sorted().collect(toList()),
                keyIds);

        mongoTemplate.bulkOps(BulkOperations.BulkMode.ORDERED, SigningKey.class).remove(new Query()).execute();
    }

}