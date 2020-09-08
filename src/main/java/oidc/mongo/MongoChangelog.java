package oidc.mongo;

import com.github.cloudyrock.mongock.ChangeLog;
import com.github.cloudyrock.mongock.ChangeSet;
import com.github.cloudyrock.mongock.driver.mongodb.springdata.v3.decorator.impl.MongockTemplate;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.IdentityProvider;
import oidc.model.OpenIDClient;
import oidc.model.RefreshToken;
import oidc.model.SigningKey;
import oidc.model.SymmetricKey;
import oidc.model.User;
import oidc.model.UserConsent;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.index.Index;
import org.springframework.data.mongodb.core.index.IndexOperations;
import org.springframework.data.mongodb.core.query.Query;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

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

    @ChangeSet(order = "002", id = "createRefreshTokenIndex", author = "Okke Harsta")
    public void createRefreshTokenIndex(MongockTemplate mongoTemplate) {
        mongoTemplate.dropCollection(RefreshToken.class);

        Map<Class<? extends Object>, List<String>> indexInfo = new HashMap<>();

        indexInfo.put(RefreshToken.class, singletonList("innerValue"));

        ensureCollectionsAndIndexes(mongoTemplate, indexInfo);
    }

    @ChangeSet(order = "003", id = "createSigningKeyCollection", author = "Okke Harsta")
    public void createSigningKeyCollection(MongockTemplate mongoTemplate) {
        if (!mongoTemplate.collectionExists("signing_keys")) {
            mongoTemplate.createCollection("signing_keys");
        }
        IndexOperations indexOperations = mongoTemplate.indexOps(SigningKey.class);
        indexOperations.ensureIndex(new Index("created", Sort.Direction.DESC));
    }

    @ChangeSet(order = "004", id = "createSymmetricKeyCollection", author = "Okke Harsta")
    public void createSymmetricKeyCollection(MongockTemplate mongoTemplate) {
        if (!mongoTemplate.collectionExists("symmetric_keys")) {
            mongoTemplate.createCollection("symmetric_keys");
        }
        IndexOperations indexOperations = mongoTemplate.indexOps(SymmetricKey.class);
        indexOperations.ensureIndex(new Index("created", Sort.Direction.DESC));
    }

    @ChangeSet(order = "005", id = "deleteTokens", author = "Okke Harsta")
    public void deleteTokens(MongockTemplate mongoTemplate) {
        Stream.of(AccessToken.class, RefreshToken.class, AuthorizationCode.class, User.class)
                .forEach(clazz -> mongoTemplate.remove(new Query(), clazz));
    }

    @ChangeSet(order = "006", id = "createUserConsentIndex", author = "Okke Harsta")
    public void createUserConsent(MongockTemplate mongoTemplate) {
        mongoTemplate.dropCollection(UserConsent.class);

        Map<Class<? extends Object>, List<String>> indexInfo = new HashMap<>();

        indexInfo.put(UserConsent.class, singletonList("sub"));

        ensureCollectionsAndIndexes(mongoTemplate, indexInfo);
    }

    @ChangeSet(order = "007", id = "createIdentityProviders", author = "Okke Harsta")
    public void createIdentityProviders(MongockTemplate mongoTemplate) {
        mongoTemplate.dropCollection(IdentityProvider.class);

        Map<Class<? extends Object>, List<String>> indexInfo = new HashMap<>();

        indexInfo.put(IdentityProvider.class, singletonList("entityId"));

        ensureCollectionsAndIndexes(mongoTemplate, indexInfo);
    }

    @ChangeSet(order = "008", id = "removeAndRebuildRefreshTokenIndex", author = "Okke Harsta")
    public void removeAndRebuildRefreshTokenIndex(MongockTemplate mongoTemplate) {
        IndexOperations indexOperations = mongoTemplate.indexOps(RefreshToken.class);
        indexOperations.dropIndex("innerValue_unique");
        Index index = new Index("value", Sort.Direction.ASC).named(String.format("value_unique")).unique();
        indexOperations.ensureIndex(index);
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
