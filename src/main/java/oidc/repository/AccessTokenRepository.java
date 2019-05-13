package oidc.repository;

import oidc.model.AccessToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccessTokenRepository extends MongoRepository<AccessToken, String> {

    AccessToken findByValue(String value);

    Optional<AccessToken> findOptionalAccessTokenByValue(String value);
}
