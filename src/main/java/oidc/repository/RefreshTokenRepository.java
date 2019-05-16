package oidc.repository;

import oidc.model.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;

@Repository
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {

    RefreshToken findByInnerValue(String value);

    Long deleteByExpiresInBefore(Date expiryDate);

}
