package oidc.repository;

import oidc.model.IdentityProvider;
import oidc.model.OpenIDClient;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface IdentityProviderRepository extends MongoRepository<IdentityProvider, String> {

    IdentityProvider findByEntityId(String entityId);

}
