package oidc.secure;


import oidc.repository.AccessTokenRepository;
import oidc.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Configuration
@EnableScheduling
public class ResourceCleaner {

    private AccessTokenRepository accessTokenRepository;
    private RefreshTokenRepository refreshTokenRepository;
    private boolean cronJobResponsible;

    public ResourceCleaner(AccessTokenRepository accessTokenRepository,
                           RefreshTokenRepository refreshTokenRepository,
                           @Value("${cron.node-cron-job-responsible}") boolean cronJobResponsible) {
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.cronJobResponsible = cronJobResponsible;
    }

    @Scheduled(cron = "${cron.expression}")
    public void clean() {
        if (!cronJobResponsible) {
            return;
        }

    }
}
