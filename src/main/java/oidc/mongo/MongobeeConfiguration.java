package oidc.mongo;

import com.github.mongobee.Mongobee;
import com.github.mongobee.changeset.ChangeLog;
import com.github.mongobee.changeset.ChangeSet;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.OpenIDClient;
import oidc.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.MongoDbFactory;
import org.springframework.data.mongodb.MongoTransactionManager;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.index.Index;
import org.springframework.data.mongodb.core.index.IndexOperations;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@ChangeLog
public class MongobeeConfiguration {

    @Autowired
    private MongoTemplate mongoTemplate;

    @Value("${mongodb_db}")
    private String databaseName;

    @Bean
    public MongoTransactionManager transactionManager() {
        return new MongoTransactionManager(mongoTemplate.getMongoDbFactory());
    }

    @Bean
    public Mongobee mongobee() throws Exception {
        return new Mongobee().setChangeLogsScanPackage("oidc.mongo").setDbName(databaseName).setMongoTemplate(mongoTemplate);
    }

    @ChangeSet(order = "001", id = "createIndexes", author = "Okke Harsta")
    public void createCollections(MongoTemplate mongoTemplate) {
        Map<Class<? extends Object>, List<String>> indexInfo = new HashMap<>();
        indexInfo.put(AccessToken.class, Arrays.asList("value"));
        indexInfo.put(AuthorizationCode.class, Arrays.asList("code"));
        indexInfo.put(User.class, Arrays.asList("sub"));
        indexInfo.put(OpenIDClient.class, Arrays.asList("clientId"));
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
