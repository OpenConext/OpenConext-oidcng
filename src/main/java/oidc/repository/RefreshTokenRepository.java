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

    Optional<RefreshToken> findByJwtId(String jwtId);

    Long deleteByExpiresInBefore(Date expiryDate);

    List<RefreshToken> findByUnspecifiedUrnHash(String unspecifiedUrnHash);

    RefreshToken findByInnerValue(String refreshTokenValue);
}
