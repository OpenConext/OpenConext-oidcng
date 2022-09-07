package oidc.secure;

import oidc.model.AccessToken;
import oidc.model.RefreshToken;
import oidc.model.SigningKey;
import oidc.model.SymmetricKey;
import oidc.repository.SequenceRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class KeyRollover {

    private static final Log LOG = LogFactory.getLog(KeyRollover.class);

    private TokenGenerator tokenGenerator;
    private MongoTemplate mongoTemplate;
    private boolean cronJobResponsible;
    private SequenceRepository sequenceRepository;

    public KeyRollover(TokenGenerator tokenGenerator,
                       MongoTemplate mongoTemplate,
                       @Value("${cron.node-cron-job-responsible}") boolean cronJobResponsible,
                       SequenceRepository sequenceRepository) {
        this.tokenGenerator = tokenGenerator;
        this.mongoTemplate = mongoTemplate;
        this.cronJobResponsible = cronJobResponsible;
        this.sequenceRepository = sequenceRepository;
    }

    @Scheduled(cron = "${cron.key-rollover-expression}")
    public void rollover() {
        if (!cronJobResponsible) {
            return;
        }
        doSigningKeyRollover();
    }

    public List<String> doSigningKeyRollover() {
        try {
            SigningKey signingKey = tokenGenerator.rolloverSigningKeys();
            LOG.info("Successful signing key rollover. New signing key: " + signingKey.getKeyId());

            return cleanUpSigningKeys();
        } catch (Exception e) {
            LOG.error("Rollover exception", e);
            return Collections.emptyList();
        }
    }

    public List<String> doSymmetricKeyRollover() {
        try {
            SymmetricKey symmetricKey = tokenGenerator.rolloverSymmetricKeys();
            LOG.info("Successful symmetric key rollover. New symmetric key: " + symmetricKey.getKeyId());

            return cleanUpSymmetricKeys();
        } catch (Exception e) {
            LOG.error("Rollover exception", e);
            return Collections.emptyList();
        }
    }

    public List<String> cleanUpSigningKeys() {
        List<String> signingKeyValues = mongoTemplate.findDistinct("signingKeyId", AccessToken.class, String.class);
        List<String> signingKeyValuesRefreshToken = mongoTemplate.findDistinct("signingKeyId", RefreshToken.class, String.class);
        signingKeyValues.addAll(signingKeyValuesRefreshToken);

        signingKeyValues.add(sequenceRepository.currentSigningKeyId());

        Query query = Query.query(Criteria.where("keyId").not().in(signingKeyValues));
        List<SigningKey> signingKeys = mongoTemplate.findAllAndRemove(query, SigningKey.class);

        List<String> deleted = signingKeys.stream().map(SigningKey::getKeyId).collect(Collectors.toList());
        String deletedKeys = deleted.isEmpty() ? "None" : String.join(", ", deleted);
        LOG.info("Deleted signing keys that are no longer referenced by access_tokens and refresh_token: " + deletedKeys);

        return deleted;
    }

    public List<String> cleanUpSymmetricKeys() {
        List<String> symmetricKeyValues = mongoTemplate.findDistinct("symmetricKeyId", SigningKey.class, String.class);
        symmetricKeyValues.add(sequenceRepository.currentSymmetricKeyId());

        Query query = Query.query(Criteria.where("keyId").not().in(symmetricKeyValues));
        List<SymmetricKey> symmetricKeys = mongoTemplate.findAllAndRemove(query, SymmetricKey.class);

        List<String> deleted = symmetricKeys.stream().map(SymmetricKey::getKeyId).collect(Collectors.toList());
        String deletedKeys = deleted.isEmpty() ? "None" : String.join(", ", deleted);
        LOG.info("Deleted symmetric keys that are no longer referenced by signing keys: " + deletedKeys);

        return deleted;
    }
}
