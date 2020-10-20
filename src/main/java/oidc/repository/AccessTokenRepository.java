package oidc.repository;

import oidc.model.AccessToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Repository
public interface AccessTokenRepository extends MongoRepository<AccessToken, String> {

    Optional<AccessToken> findByJwtId(String jwtId);

    Long deleteByExpiresInBefore(Date expiryDate);

    Long deleteByAuthorizationCodeId(String authorizationCodeId);

    List<AccessToken> findByUnspecifiedUrnHash(String unspecifiedUrnHash);

}
