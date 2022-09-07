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

    private final FindAndModifyOptions options = FindAndModifyOptions.options().returnNew(true);
    private final MongoTemplate mongoTemplate;

    private final BasicQuery signingKeyBasicQuery = new BasicQuery(String.format("{\"_id\":\"%s\"}", SIGNING_KEY_ID));
    private final BasicQuery symmetricKeyBasicQuery = new BasicQuery(String.format("{\"_id\":\"%s\"}", SYMMETRIC_KEY_ID));

    @Autowired
    public SequenceRepository(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    public void updateSigningKeyId(String newKeyId) {
        doUpdateKeyId(newKeyId, signingKeyBasicQuery, SIGNING_KEY_ID);
    }

    public void updateSymmetricKeyId(String newKeyId) {
        doUpdateKeyId(newKeyId, symmetricKeyBasicQuery, SYMMETRIC_KEY_ID);
    }

    private void doUpdateKeyId(String newKeyId, BasicQuery signingKeyBasicQuery, String signingKeyId) {
        Sequence res = mongoTemplate.findAndModify(signingKeyBasicQuery, Update.update("value", newKeyId), options, Sequence.class);
        if (res == null) {
            mongoTemplate.save(new Sequence(signingKeyId, newKeyId));
        }
    }

    public String getLatestSigningKeyId() {
        return getSequenceValue(signingKeyBasicQuery);
    }

    public String getLatestSymmetricKeyId() {
        return getSequenceValue(symmetricKeyBasicQuery);
    }

    private String getSequenceValue(BasicQuery basicQuery) {
        Sequence one = mongoTemplate.findOne(basicQuery, Sequence.class);
        if (one == null) {
            return "nope";
        }
        return one.getValue();
    }


}
