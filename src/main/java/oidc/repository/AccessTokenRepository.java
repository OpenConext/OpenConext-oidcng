package oidc.repository;

import oidc.model.AccessToken;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.data.domain.Example;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccessTokenRepository extends MongoRepository<AccessToken, String> {

    default AccessToken findByValue(String value) {
        Optional<AccessToken> one = findOne(Example.of(AccessToken.fromValue(value)));
        return one.orElseThrow(() -> new EmptyResultDataAccessException("AccessToken not found", 1));
    }

    default Optional<AccessToken> findOptionalAccessTokenByValue(String value) {
        return findOne(Example.of(AccessToken.fromValue(value)));
    }
}
