package oidc.repository;

import oidc.model.Sequence;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.BasicQuery;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Repository;

@Repository
public class SequenceRepository {

    private FindAndModifyOptions options = FindAndModifyOptions.options().returnNew(true);
    private MongoTemplate mongoTemplate;

    private BasicQuery basicQuery = new BasicQuery(String.format("{\"_id\":\"%s\"}", Sequence.ID_VALUE));

    @Autowired
    public SequenceRepository(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    public Long increment() {
        Update updateInc = new Update();
        updateInc.inc("value", 1L);
        Sequence res = mongoTemplate.findAndModify(basicQuery, updateInc, options, Sequence.class);
        if (res == null) {
            mongoTemplate.save(new Sequence(Sequence.ID_VALUE, 1L));
            return 1L;
        }
        return res.getValue();
    }

    public Long currentSequence() {
        return mongoTemplate.findOne(basicQuery, Sequence.class).getValue();
    }
}
