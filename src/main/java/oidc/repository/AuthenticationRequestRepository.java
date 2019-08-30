package oidc.repository;

import oidc.model.AuthenticationRequest;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Date;

public interface AuthenticationRequestRepository extends MongoRepository<AuthenticationRequest, String> {

    Long deleteByExpiresInBefore(Date expiryDate);
}
