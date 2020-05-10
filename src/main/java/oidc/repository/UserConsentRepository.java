package oidc.repository;

import oidc.model.AccessToken;
import oidc.model.UserConsent;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.nio.charset.Charset;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserConsentRepository extends MongoRepository<UserConsent, String> {

    Optional<UserConsent> findUserConsentBySub(String sub);
}
