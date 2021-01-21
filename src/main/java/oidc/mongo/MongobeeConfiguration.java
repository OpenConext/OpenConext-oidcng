package oidc.mongo;

import com.github.mongobee.Mongobee;
import com.github.mongobee.changeset.ChangeLog;
import com.github.mongobee.changeset.ChangeSet;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.IdentityProvider;
import oidc.model.OpenIDClient;
import oidc.model.RefreshToken;
import oidc.model.SigningKey;
import oidc.model.SymmetricKey;
import oidc.model.User;
import oidc.model.UserConsent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.MongoTransactionManager;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.index.Index;
import org.springframework.data.mongodb.core.index.IndexOperations;
import org.springframework.data.mongodb.core.query.Query;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;

@Configuration
@ChangeLog
public class MongobeeConfiguration {

    @Autowired
    private MongoTemplate mongoTemplate;

    @Value("${mongodb_db}")
    private String databaseName;


    @Value("${spring.data.mongodb.uri}")
    private String mongobdUri;

    @Bean
    public MongoTransactionManager transactionManager() {
        return new MongoTransactionManager(mongoTemplate.getMongoDbFactory());
    }

    @Bean
    public Mongobee mongobee(@Value("${spring.data.mongodb.uri}") String mongobdUri) throws Exception {
        Mongobee mongobee = new Mongobee(new MongoClient(new MongoClientURI(mongobdUri)));
        return mongobee
                .setChangeLogsScanPackage("oidc.mongo")
                .setDbName(databaseName)
                .setMongoTemplate(mongoTemplate);
    }

    @ChangeSet(order = "001", id = "createIndexes", author = "Okke Harsta")
    public void createCollections(MongoTemplate mongoTemplate) {
        Map<Class<? extends Object>, List<String>> indexInfo = new HashMap<>();

        indexInfo.put(AccessToken.class, singletonList("value"));
        indexInfo.put(AuthorizationCode.class, singletonList("code"));
        indexInfo.put(User.class, singletonList("sub"));
        indexInfo.put(OpenIDClient.class, singletonList("clientId"));

        ensureCollectionsAndIndexes(mongoTemplate, indexInfo);
    }

    @ChangeSet(order = "002", id = "createRefreshTokenIndex", author = "Okke Harsta")
    public void createRefreshTokenIndex(MongoTemplate mongoTemplate) {
        mongoTemplate.dropCollection(RefreshToken.class);

        Map<Class<? extends Object>, List<String>> indexInfo = new HashMap<>();

        indexInfo.put(RefreshToken.class, singletonList("innerValue"));

        ensureCollectionsAndIndexes(mongoTemplate, indexInfo);
    }

    @ChangeSet(order = "003", id = "createSigningKeyCollection", author = "Okke Harsta")
    public void createSigningKeyCollection(MongoTemplate mongoTemplate) {
        if (!mongoTemplate.collectionExists("signing_keys")) {
            mongoTemplate.createCollection("signing_keys");
        }
        IndexOperations indexOperations = mongoTemplate.indexOps(SigningKey.class);
        indexOperations.ensureIndex(new Index("created", Sort.Direction.DESC));
    }

    @ChangeSet(order = "004", id = "createSymmetricKeyCollection", author = "Okke Harsta")
    public void createSymmetricKeyCollection(MongoTemplate mongoTemplate) {
        if (!mongoTemplate.collectionExists("symmetric_keys")) {
            mongoTemplate.createCollection("symmetric_keys");
        }
        IndexOperations indexOperations = mongoTemplate.indexOps(SymmetricKey.class);
        indexOperations.ensureIndex(new Index("created", Sort.Direction.DESC));
    }

    @ChangeSet(order = "005", id = "deleteTokens", author = "Okke Harsta")
    public void deleteTokens(MongoTemplate mongoTemplate) {
        Stream.of(AccessToken.class, RefreshToken.class, AuthorizationCode.class, User.class)
                .forEach(clazz -> mongoTemplate.remove(new Query(), clazz));
    }

    @ChangeSet(order = "006", id = "createUserConsentIndex", author = "Okke Harsta")
    public void createUserConsent(MongoTemplate mongoTemplate) {
        mongoTemplate.dropCollection(UserConsent.class);

        Map<Class<? extends Object>, List<String>> indexInfo = new HashMap<>();

        indexInfo.put(UserConsent.class, singletonList("sub"));

        ensureCollectionsAndIndexes(mongoTemplate, indexInfo);
    }

    @ChangeSet(order = "007", id = "createIdentityProviders", author = "Okke Harsta")
    public void createIdentityProviders(MongoTemplate mongoTemplate) {
        mongoTemplate.dropCollection(IdentityProvider.class);

        Map<Class<? extends Object>, List<String>> indexInfo = new HashMap<>();

        indexInfo.put(IdentityProvider.class, singletonList("entityId"));

        ensureCollectionsAndIndexes(mongoTemplate, indexInfo);
    }

    @ChangeSet(order = "008", id = "migrateTokens", author = "Okke Harsta")
    public void migrateTokens(MongoTemplate mongoTemplate) {
//        mongoTemplate.find()
    }

    private void ensureCollectionsAndIndexes(MongoTemplate mongoTemplate, Map<Class<?>, List<String>> indexInfo) {
        ensureCollectionsAndIndexes(mongoTemplate, indexInfo, true);
    }

    private void ensureCollectionsAndIndexes(MongoTemplate mongoTemplate, Map<Class<?>, List<String>> indexInfo, boolean unique) {
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
