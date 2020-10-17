package oidc.repository;

import oidc.model.UserConsent;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.Optional;

@Repository
public interface UserConsentRepository extends MongoRepository<UserConsent, String> {

    Optional<UserConsent> findUserConsentBySub(String sub);

    Long deleteByLastAccessedBefore(Date expiryDate);
}
