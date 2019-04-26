package oidc.repository;

import oidc.model.AccessToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccessTokenRepository extends MongoRepository<AccessToken, String> {

    AccessToken findByValue(String value);
}
