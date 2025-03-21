package oidc.repository;

import oidc.model.AuthenticationRequest;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;

@Repository
public interface AuthenticationRequestRepository extends MongoRepository<AuthenticationRequest, String> {

    Long deleteByExpiresInBefore(Date expiryDate);
}
