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
        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            LOG.error("Rollover exception", e);
        }
    }


}
