package oidc.repository;

import oidc.model.Sequence;
import oidc.model.SigningKey;
import oidc.model.SymmetricKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.BasicQuery;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Repository;

@Repository
public class SequenceRepository {

    private static final String SIGNING_KEY_ID = SigningKey.class.getSimpleName();
    private static final String SYMMETRIC_KEY_ID = SymmetricKey.class.getSimpleName();

    private FindAndModifyOptions options = FindAndModifyOptions.options().returnNew(true);
    private MongoTemplate mongoTemplate;

    private BasicQuery signingKeyBasicQuery = new BasicQuery(String.format("{\"_id\":\"%s\"}", SIGNING_KEY_ID));
    private BasicQuery symmetricKeyBasicQuery = new BasicQuery(String.format("{\"_id\":\"%s\"}", SYMMETRIC_KEY_ID));

    @Autowired
    public SequenceRepository(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    public Long incrementSigningKeyId() {
        Update updateInc = new Update();
        updateInc.inc("value", 1L);
        Sequence res = mongoTemplate.findAndModify(signingKeyBasicQuery, updateInc, options, Sequence.class);
        if (res == null) {
            mongoTemplate.save(new Sequence(SIGNING_KEY_ID, 1L));
            return 1L;
        }
        return res.getValue();
    }

    public Long currentSigningKeyId() {
        Sequence one = mongoTemplate.findOne(signingKeyBasicQuery, Sequence.class);
        if (one == null) {
            return -1L;
        }
        return one.getValue();
    }

    public void updateSymmetricKeyId(Long newKeyId) {
        Sequence res = mongoTemplate.findAndModify(symmetricKeyBasicQuery, Update.update("value", newKeyId), options, Sequence.class);
        if (res == null) {
            mongoTemplate.save(new Sequence(SYMMETRIC_KEY_ID, newKeyId));
        }
    }

    public Long currentSymmetricKeyId() {
        Sequence one = mongoTemplate.findOne(symmetricKeyBasicQuery, Sequence.class);
        if (one == null) {
            return -1L;
        }
        return one.getValue();
    }
}
