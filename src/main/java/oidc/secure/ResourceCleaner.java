package oidc.secure;


import oidc.model.AccessToken;
import oidc.model.AuthorizationCode;
import oidc.model.RefreshToken;
import oidc.model.User;
import oidc.repository.AccessTokenRepository;
import oidc.repository.AuthorizationCodeRepository;
import oidc.repository.RefreshTokenRepository;
import oidc.repository.UserRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class ResourceCleaner {

    private static final Log LOG = LogFactory.getLog(ResourceCleaner.class);

    private AccessTokenRepository accessTokenRepository;
    private RefreshTokenRepository refreshTokenRepository;
    private AuthorizationCodeRepository authorizationCodeRepository;
    private UserRepository userRepository;
    private boolean cronJobResponsible;

    @Autowired
    public ResourceCleaner(AccessTokenRepository accessTokenRepository,
                           RefreshTokenRepository refreshTokenRepository,
                           AuthorizationCodeRepository authorizationCodeRepository,
                           UserRepository userRepository,
                           @Value("${cron.node-cron-job-responsible}") boolean cronJobResponsible) {
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.userRepository = userRepository;
        this.cronJobResponsible = cronJobResponsible;
    }

    @Scheduled(cron = "${cron.token-cleaner-expression}")
    public void clean() {
        if (!cronJobResponsible) {
            return;
        }
        Date now = new Date();
        info(AccessToken.class, accessTokenRepository.deleteByExpiresInBefore(now));
        info(RefreshToken.class, refreshTokenRepository.deleteByExpiresInBefore(now));
        info(AuthorizationCode.class, authorizationCodeRepository.deleteByExpiresInBefore(now));

        List<String> subs = authorizationCodeRepository.findSub().stream().map(AuthorizationCode::getSub).collect(Collectors.toList());
        info(User.class, userRepository.deleteBySubNotIn(subs));
    }

    private void info(Class clazz, long count) {
        LOG.info(String.format("Deleted %s instances of %s", count, clazz));
    }
}
