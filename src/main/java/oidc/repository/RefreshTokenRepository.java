package oidc.repository;

import oidc.model.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

@Repository
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {

    RefreshToken findByInnerValue(String value);

    Long deleteByExpiresInBefore(Date expiryDate);

    List<RefreshToken> findAccessTokenByUnspecifiedUrnHash(String unspecifiedUrnHash);

}
