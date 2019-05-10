package oidc.mongo;

import com.mongodb.MongoClient;
import com.mongodb.ReplicaSetStatus;
import com.mongodb.client.internal.MongoClientDelegate;
import com.mongodb.connection.ClusterDescription;
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
        ReplicaSetStatus replicaSetStatus = mongoClient.getReplicaSetStatus();
        MongoClientDelegate delegate = (MongoClientDelegate) ReflectionTestUtils.getField(mongoClient, "delegate");
        ClusterDescription clusterDescription= delegate.getCluster().getCurrentDescription();
        return Health.up()
                .withDetail("Cluster", clusterDescription)
                .withDetail("ReplicaSetStatus", replicaSetStatus != null ? replicaSetStatus : "No replica status")
                .build();
    }
}
