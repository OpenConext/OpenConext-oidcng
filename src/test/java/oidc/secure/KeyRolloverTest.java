package oidc.secure;

import oidc.AbstractIntegrationTest;
import oidc.SeedUtils;
import oidc.model.AccessToken;
import oidc.model.SigningKey;
import org.junit.Test;
import org.springframework.data.mongodb.core.BulkOperations;
import org.springframework.data.mongodb.core.query.Query;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertEquals;

public class KeyRolloverTest extends AbstractIntegrationTest implements SeedUtils {

    @Test
    public void rollover() throws NoSuchProviderException, NoSuchAlgorithmException {
        resetAndCreateSigningKeys(3);
        List<AccessToken> tokens = IntStream.rangeClosed(0, 5).mapToObj(i -> accessToken("val" + i, "key_" + (i % 2))).collect(toList());
        mongoTemplate.bulkOps(BulkOperations.BulkMode.ORDERED, AccessToken.class)
                .remove(new Query())
                .insert(tokens)
                .execute();

        KeyRollover keyRollover = new KeyRollover(tokenGenerator, mongoTemplate, true);
        keyRollover.rollover();

        assertEquals(Arrays.asList("key_1", "key_4"),
                mongoTemplate.findAll(SigningKey.class).stream().map(signingKey -> signingKey.getKeyId()).sorted().collect(toList()));

    }
}