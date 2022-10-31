package oidc.repository;

import oidc.model.SamlAuthenticationRequest;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SamlAuthenticationRequestRepository extends MongoRepository<SamlAuthenticationRequest, String> {
}
