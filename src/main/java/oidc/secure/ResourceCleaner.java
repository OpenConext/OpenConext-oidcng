package oidc.secure;


import oidc.model.AccessToken;
import oidc.model.AuthenticationRequest;
import oidc.model.AuthorizationCode;
import oidc.model.RefreshToken;
import oidc.model.User;
import oidc.model.UserConsent;
import oidc.repository.AccessTokenRepository;
import oidc.repository.AuthenticationRequestRepository;
import oidc.repository.AuthorizationCodeRepository;
import oidc.repository.RefreshTokenRepository;
import oidc.repository.UserConsentRepository;
import oidc.repository.UserRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class ResourceCleaner {

    private static final Log LOG = LogFactory.getLog(ResourceCleaner.class);

    private final AccessTokenRepository accessTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final UserRepository userRepository;
    private final UserConsentRepository userConsentRepository;
    private final AuthenticationRequestRepository authenticationRequestRepository;
    private final boolean cronJobResponsible;
    private final long consentExpiryDurationDays;

    @Autowired
    public ResourceCleaner(AccessTokenRepository accessTokenRepository,
                           RefreshTokenRepository refreshTokenRepository,
                           AuthorizationCodeRepository authorizationCodeRepository,
                           UserRepository userRepository,
                           UserConsentRepository userConsentRepository,
                           AuthenticationRequestRepository authenticationRequestRepository,
                           @Value("${cron.consent-expiry-duration-days}") long consentExpiryDurationDays,
                           @Value("${cron.node-cron-job-responsible}") boolean cronJobResponsible) {
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.userRepository = userRepository;
        this.authenticationRequestRepository = authenticationRequestRepository;
        this.consentExpiryDurationDays = consentExpiryDurationDays;
        this.userConsentRepository = userConsentRepository;
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
        info(AuthenticationRequest.class, authenticationRequestRepository.deleteByExpiresInBefore(now));

        List<String> subs = authorizationCodeRepository.findSub().stream().map(AuthorizationCode::getSub).collect(Collectors.toList());
        info(User.class, userRepository.deleteBySubNotIn(subs));

        Date userConsentExpiryDate = Date.from(now.toInstant().minus(consentExpiryDurationDays, ChronoUnit.DAYS).atZone(ZoneId.systemDefault()).toInstant());
        info(UserConsent.class, userConsentRepository.deleteByLastAccessedBefore(userConsentExpiryDate));
    }

    private void info(Class clazz, long count) {
        LOG.info(String.format("Deleted %s instances of %s", count, clazz));
    }
}
