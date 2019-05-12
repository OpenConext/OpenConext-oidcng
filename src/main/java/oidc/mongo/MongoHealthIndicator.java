package oidc.mongo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.SimpleMongoDbFactory;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@Component
public class MongoHealthIndicator implements HealthIndicator {

    private MongoTemplate mongoTemplate;

    @Autowired
    public MongoHealthIndicator(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    @Override
    public Health health() {
        SimpleMongoDbFactory mongoDbFactory = (SimpleMongoDbFactory) mongoTemplate.getMongoDbFactory();
        String collections = StreamSupport.stream(mongoTemplate.getDb().listCollectionNames().spliterator(), false).collect(Collectors.joining(", "));
        return Health.up()
                .withDetail("Collections", collections)
                .build();
    }
}
