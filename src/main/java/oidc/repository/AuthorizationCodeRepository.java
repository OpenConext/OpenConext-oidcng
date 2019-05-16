package oidc.repository;

import oidc.model.AuthorizationCode;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;

@Repository
public interface AuthorizationCodeRepository extends MongoRepository<AuthorizationCode, String> {

    AuthorizationCode findByCode(String code);

    Long deleteByExpiresInBefore(Date expiryDate);

}
