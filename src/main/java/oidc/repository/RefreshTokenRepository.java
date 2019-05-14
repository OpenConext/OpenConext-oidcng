package oidc.repository;

import oidc.model.AccessToken;
import oidc.model.RefreshToken;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.data.domain.Example;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {

    RefreshToken findByInnerValue(String value);
}
