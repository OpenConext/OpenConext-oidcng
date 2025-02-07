package oidc.repository;

import oidc.model.AccessToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.nio.charset.Charset;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AccessTokenRepository extends MongoRepository<AccessToken, String> {

    Optional<AccessToken> findByJwtId(String jwtId);

    Long deleteByExpiresInBefore(Date expiryDate);

    List<AccessToken> findByAuthorizationCodeId(String authorizationCodeId);

    List<AccessToken> findByUnspecifiedUrnHash(String unspecifiedUrnHash);

    //For backward compatibility. Delete if all refresh_tokens are JWT's
    default Optional<AccessToken> findOptionalAccessTokenByValue(String value) {
        String newValue = UUID.nameUUIDFromBytes(value.getBytes(Charset.defaultCharset())).toString();
        return findAccessTokenByValue(newValue);
    }

    //Do not use
    Optional<AccessToken> findAccessTokenByValue(String value);

}
