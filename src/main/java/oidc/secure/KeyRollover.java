package oidc.secure;

import oidc.model.SigningKey;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

@Component
public class KeyRollover {

    private static final Log LOG = LogFactory.getLog(KeyRollover.class);

    private TokenGenerator tokenGenerator;
    private boolean cronJobResponsible;

    public KeyRollover(TokenGenerator tokenGenerator,
                       @Value("${cron.node-cron-job-responsible}") boolean cronJobResponsible) {
        this.tokenGenerator = tokenGenerator;
        this.cronJobResponsible = cronJobResponsible;
    }

    @Scheduled(cron = "${cron.key-rollover-expression}")
    public void clean() {
        if (!cronJobResponsible) {
            return;
        }
        try {
            SigningKey signingKey = tokenGenerator.rolloverSigningKeys();
            LOG.info("Successful signing key rollover. New signing key: " + signingKey.getKeyId());
            //TODO clean up keys that are not used in any access_tokens
            //see https://stackoverflow.com/questions/37077687/spring-data-mongo-query-methods-and-distinct-field
            //see https://docs.spring.io/spring-data/mongodb/docs/1.4.1.RELEASE/reference/htmlsingle/ 322
        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            LOG.error("Rollover exception", e);
        }
    }


}
