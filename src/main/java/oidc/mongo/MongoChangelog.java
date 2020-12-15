package oidc.mongo;

import com.github.cloudyrock.mongock.ChangeLog;
import com.github.cloudyrock.mongock.ChangeSet;
import com.github.cloudyrock.mongock.driver.mongodb.springdata.v3.decorator.impl.MongockTemplate;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.OpenIDClient;
import oidc.model.RefreshToken;
import oidc.model.SigningKey;
import oidc.model.SymmetricKey;
import oidc.model.User;
import oidc.model.UserConsent;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.index.Index;
import org.springframework.data.mongodb.core.index.IndexOperations;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;

@ChangeLog(order = "001")
public class MongoChangelog {

    @ChangeSet(order = "001", id = "createIndexes", author = "Okke Harsta")
    public void createCollections(MongockTemplate mongoTemplate) {
        Map<Class<? extends Object>, List<String>> indexInfo = new HashMap<>();

        indexInfo.put(AccessToken.class, singletonList("value"));
        indexInfo.put(AuthorizationCode.class, singletonList("code"));
        indexInfo.put(User.class, singletonList("sub"));
        indexInfo.put(OpenIDClient.class, singletonList("clientId"));

        ensureCollectionsAndIndexes(mongoTemplate, indexInfo);
    }

    @ChangeSet(order = "002", id = "createSigningAndSymmetricKeyCollection", author = "Okke Harsta")
    public void createSigningKeyCollection(MongockTemplate mongoTemplate) {
        if (!mongoTemplate.collectionExists("signing_keys")) {
            mongoTemplate.createCollection("signing_keys");
        }
        mongoTemplate.indexOps(SigningKey.class).ensureIndex(new Index("created", Sort.Direction.DESC));

        if (!mongoTemplate.collectionExists("symmetric_keys")) {
            mongoTemplate.createCollection("symmetric_keys");
        }
        mongoTemplate.indexOps(SymmetricKey.class).ensureIndex(new Index("created", Sort.Direction.DESC));
    }

    @ChangeSet(order = "003", id = "createUserConsentIndex", author = "Okke Harsta")
    public void createUserConsent(MongockTemplate mongoTemplate) {
        mongoTemplate.dropCollection(UserConsent.class);
        Map<Class<? extends Object>, List<String>> indexInfo = new HashMap<>();
        indexInfo.put(UserConsent.class, singletonList("sub"));
        ensureCollectionsAndIndexes(mongoTemplate, indexInfo);
    }

    @ChangeSet(order = "004", id = "createIdentityProviders", author = "Okke Harsta")
    public void createIdentityProviders(MongockTemplate mongoTemplate) {
        mongoTemplate.dropCollection("identity_providers");
    }

    @ChangeSet(order = "005", id = "removeAndRebuildRefreshTokenIndex", author = "Okke Harsta")
    public void removeAndRebuildRefreshTokenIndex(MongockTemplate mongoTemplate) {
        mongoTemplate.indexOps(RefreshToken.class)
                .ensureIndex(new Index("value", Sort.Direction.ASC).named(String.format("value_unique")).unique());
    }

    @ChangeSet(order = "006", id = "dropValueIndexes", author = "Okke Harsta")
    public void dropValueIndexes(MongockTemplate mongoTemplate) {
        Arrays.asList("access_tokens", "refresh_tokens").forEach(collection -> {
            IndexOperations indexOperations = mongoTemplate.indexOps(collection);
            //This will not drop the '_id' index
            indexOperations.dropAllIndexes();
            indexOperations.ensureIndex(new Index("jwtId", Sort.Direction.ASC));
        });
    }


    private void ensureCollectionsAndIndexes(MongockTemplate mongoTemplate, Map<Class<?>, List<String>> indexInfo) {
        ensureCollectionsAndIndexes(mongoTemplate, indexInfo, true);
    }

    private void ensureCollectionsAndIndexes(MongockTemplate mongoTemplate, Map<Class<?>, List<String>> indexInfo, boolean unique) {
        indexInfo.forEach((collection, fields) -> {
            if (!mongoTemplate.collectionExists(collection)) {
                mongoTemplate.createCollection(collection);
            }
            fields.forEach(field -> {
                IndexOperations indexOperations = mongoTemplate.indexOps(collection);
                Index index = new Index(field, Sort.Direction.ASC).named(String.format("%s_unique", field));
                index = unique ? index.unique() : index;
                indexOperations.ensureIndex(index);
            });
        });
    }

}
