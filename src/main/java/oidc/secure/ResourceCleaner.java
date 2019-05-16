package oidc.secure;


import oidc.repository.AccessTokenRepository;
import oidc.repository.AuthorizationCodeRepository;
import oidc.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.Date;

@Configuration
@EnableScheduling
public class ResourceCleaner {

    private AccessTokenRepository accessTokenRepository;
    private RefreshTokenRepository refreshTokenRepository;
    private AuthorizationCodeRepository authorizationCodeRepository;
    private boolean cronJobResponsible;

    public ResourceCleaner(AccessTokenRepository accessTokenRepository,
                           RefreshTokenRepository refreshTokenRepository,
                           AuthorizationCodeRepository authorizationCodeRepository,
                           @Value("${cron.node-cron-job-responsible}") boolean cronJobResponsible) {
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.cronJobResponsible = cronJobResponsible;
    }

    @Scheduled(cron = "${cron.expression}")
    public void clean() {
        if (!cronJobResponsible) {
            return;
        }
        Date now = new Date();
        accessTokenRepository.deleteByExpiresInBefore(now);
        refreshTokenRepository.deleteByExpiresInBefore(now);
        authorizationCodeRepository.deleteByExpiresInBefore(now);
    }
}
