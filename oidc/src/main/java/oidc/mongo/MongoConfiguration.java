package oidc.mongo;

import com.github.cloudyrock.mongock.driver.mongodb.springdata.v3.SpringDataMongoV3Driver;
import com.github.cloudyrock.spring.v5.MongockSpring5;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.MongoTransactionManager;
import org.springframework.data.mongodb.core.MongoTemplate;

@Configuration
public class MongoConfiguration {

    @Autowired
    private MongoTemplate mongoTemplate;

    @Bean
    public MongoTransactionManager transactionManager() {
        return new MongoTransactionManager(mongoTemplate.getMongoDatabaseFactory());
    }

    @Bean
    public MongockSpring5.MongockApplicationRunner mongockApplicationRunner(ApplicationContext springContext,
                                                                            MongoTemplate mongoTemplate) {
        SpringDataMongoV3Driver driver = SpringDataMongoV3Driver.withDefaultLock(mongoTemplate);
        driver.disableTransaction();

        return MongockSpring5.builder()
                .setDriver(driver)
                .addChangeLogsScanPackage("oidc.mongo")
                .setSpringContext(springContext)
                .buildApplicationRunner();
    }

}
