package oidc.repository;

import oidc.model.AccessToken;
import oidc.model.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {

    default Optional<RefreshToken> findOptionalRefreshTokenByValue(String value) {
        String newValue = AccessToken.computeInnerValueFromJWT(value);
        return findRefreshTokenByValue(newValue);
    }

    Long deleteByExpiresInBefore(Date expiryDate);

    List<RefreshToken> findRefreshTokenByUnspecifiedUrnHash(String unspecifiedUrnHash);

    //Do not use
    Optional<RefreshToken> findRefreshTokenByValue(String value);

}
