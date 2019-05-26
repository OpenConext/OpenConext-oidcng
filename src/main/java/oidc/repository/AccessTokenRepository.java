package oidc.repository;

import oidc.model.AccessToken;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.nio.charset.Charset;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AccessTokenRepository extends MongoRepository<AccessToken, String> {

    default AccessToken findByValue(String value) {
        Optional<AccessToken> accessToken = findOptionalAccessTokenByValue(value);
        return accessToken.orElseThrow(() -> new EmptyResultDataAccessException("AccessToken not found", 1));
    }

    default Optional<AccessToken> findOptionalAccessTokenByValue(String value) {
        String newValue = UUID.nameUUIDFromBytes(value.getBytes(Charset.defaultCharset())).toString();
        return findAccessTokenByValue(newValue);
    }

    Long deleteByExpiresInBefore(Date expiryDate);

    //Do not use
    Optional<AccessToken> findAccessTokenByValue(String value);
}
