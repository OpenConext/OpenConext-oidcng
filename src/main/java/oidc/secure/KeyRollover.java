package oidc.secure;

import oidc.model.AccessToken;
import oidc.model.SigningKey;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class KeyRollover {

    private static final Log LOG = LogFactory.getLog(KeyRollover.class);

    private TokenGenerator tokenGenerator;
    private MongoTemplate mongoTemplate;
    private boolean cronJobResponsible;

    public KeyRollover(TokenGenerator tokenGenerator,
                       MongoTemplate mongoTemplate,
                       @Value("${cron.node-cron-job-responsible}") boolean cronJobResponsible) {
        this.tokenGenerator = tokenGenerator;
        this.mongoTemplate = mongoTemplate;
        this.cronJobResponsible = cronJobResponsible;
    }

    @Scheduled(cron = "${cron.key-rollover-expression}")
    public void rollover() {
        if (!cronJobResponsible) {
            return;
        }
        doRollover();
    }

    public void doRollover() {
        try {
            SigningKey signingKey = tokenGenerator.rolloverSigningKeys();
            LOG.info("Successful signing key rollover. New signing key: " + signingKey.getKeyId());

            cleanUpSigningKeys();
        } catch (Exception e) {
            LOG.error("Rollover exception", e);
        }
    }

    private void cleanUpSigningKeys() {
        List<String> signingKeyValues = mongoTemplate.findDistinct("signingKeyId", AccessToken.class, String.class);
        signingKeyValues.add(tokenGenerator.getCurrentSigningKeyId());

        Query query = Query.query(Criteria.where("keyId").not().in(signingKeyValues));
        List<SigningKey> signingKeys = mongoTemplate.findAllAndRemove(query, SigningKey.class);

        List<String> deleted = signingKeys.stream().map(SigningKey::getKeyId).collect(Collectors.toList());
        LOG.info("Deleted signing keys that are no longer referenced by access_tokens: " + String.join(", ", deleted));
    }

}
