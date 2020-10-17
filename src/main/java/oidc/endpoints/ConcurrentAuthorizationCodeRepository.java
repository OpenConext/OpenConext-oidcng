package oidc.endpoints;

import oidc.model.AuthorizationCode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Repository;

/**
 * We don't want this in the repository package as the contract in the 'package-info.html' enforces
 * not-null's
 */
@Repository
public class ConcurrentAuthorizationCodeRepository {

    private FindAndModifyOptions options = FindAndModifyOptions.options().returnNew(true);
    private MongoTemplate mongoTemplate;

    @Autowired
    public ConcurrentAuthorizationCodeRepository(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    public AuthorizationCode findByCodeNotAlreadyUsedAndMarkAsUsed(String code) {
        Query query = new Query(Criteria.where("code").is(code).and("alreadyUsed").is(false));
        return mongoTemplate.findAndModify(query, Update.update("alreadyUsed", true), options, AuthorizationCode.class);
    }

}
