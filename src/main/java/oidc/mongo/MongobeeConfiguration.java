package oidc.mongo;

import com.github.mongobee.Mongobee;
import com.github.mongobee.changeset.ChangeLog;
import com.github.mongobee.changeset.ChangeSet;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.OpenIDClient;
import oidc.model.RefreshToken;
import oidc.model.Sequence;
import oidc.model.SigningKey;
import oidc.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.MongoTransactionManager;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.index.Index;
import org.springframework.data.mongodb.core.index.IndexOperations;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
        if (mongoTemplate.collectionExists("signing_keys")) {
            mongoTemplate.dropCollection("signing_keys");
        }
        mongoTemplate.createCollection("signing_keys");
        IndexOperations indexOperations = mongoTemplate.indexOps(SigningKey.class);
        indexOperations.ensureIndex(new Index("created",Sort.Direction.DESC));
    }


    private void ensureCollectionsAndIndexes(MongoTemplate mongoTemplate, Map<Class<?>, List<String>> indexInfo) {
        indexInfo.forEach((collection, fields) -> {
            if (!mongoTemplate.collectionExists(collection)) {
                mongoTemplate.createCollection(collection);
            }
            fields.forEach(field -> {
                IndexOperations indexOperations = mongoTemplate.indexOps(collection);
                indexOperations.ensureIndex(new Index(field, Sort.Direction.ASC).named(String.format("%s_unique", field)).unique());
            });
        });
    }

}
