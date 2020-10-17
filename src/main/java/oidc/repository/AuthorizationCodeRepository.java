package oidc.repository;

import oidc.model.AuthorizationCode;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

@Repository
public interface AuthorizationCodeRepository extends MongoRepository<AuthorizationCode, String> {

    AuthorizationCode findByCode(String code);

    Long deleteByExpiresInBefore(Date expiryDate);

    @Query(value = "{}", fields = "{sub : 1, _id : 0}")
    List<AuthorizationCode> findSub();

}
