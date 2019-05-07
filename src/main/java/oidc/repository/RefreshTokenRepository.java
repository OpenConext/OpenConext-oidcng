package oidc.repository;

import oidc.model.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {

    RefreshToken findByValue(String value);
}
