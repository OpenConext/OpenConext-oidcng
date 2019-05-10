package oidc.mongo;

import com.mongodb.MongoClient;
import com.mongodb.client.internal.MongoClientDelegate;
import com.mongodb.connection.ClusterType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.SimpleMongoDbFactory;
import org.springframework.stereotype.Component;
import org.springframework.test.util.ReflectionTestUtils;

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
        MongoClient mongoClient = (MongoClient) ReflectionTestUtils.getField(mongoDbFactory, "mongoClient");
        MongoClientDelegate delegate = (MongoClientDelegate) ReflectionTestUtils.getField(mongoClient, "delegate");
        ClusterType clusterType = delegate.getCluster().getCurrentDescription().getType();
        return Health.up().withDetail("Cluster", clusterType).build();
    }
}
