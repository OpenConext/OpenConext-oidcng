package oidc.repository;

import oidc.model.AccessToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Repository
public interface AccessTokenRepository extends MongoRepository<AccessToken, String> {

    default Optional<AccessToken> findOptionalAccessTokenByValue(String value) {
        String newValue = AccessToken.computeInnerValueFromJWT(value);
        return findAccessTokenByValue(newValue);
    }

    Long deleteByExpiresInBefore(Date expiryDate);

    Long deleteByAuthorizationCodeId(String authorizationCodeId);

    List<AccessToken> findAccessTokenByUnspecifiedUrnHash(String unspecifiedUrnHash);

    //Do not use
    Optional<AccessToken> findAccessTokenByValue(String value);
}
